import { useEffect, useState } from "react";
import { api } from "../api/client.js";
import { ErrorState, Loading } from "../components/DataStates.jsx";
import { fmtScore } from "../utils/format.js";

/* Explicabilité du moteur de risque : source, métriques d'entraînement,
   poids de chaque variable - transparence exigée par l'équipe Cyber. */
export default function ModelPage() {
  const [info, setInfo] = useState(null);
  const [error, setError] = useState(null);

  const load = () => {
    setError(null);
    api.modelInfo().then(setInfo).catch(setError);
  };
  useEffect(load, []);

  if (error) return <ErrorState error={error} retry={load} />;
  if (!info) return <Loading />;

  const weights = [...(info.feature_importance || [])].sort(
    (a, b) => Math.abs(b.weight) - Math.abs(a.weight)
  );
  const maxWeight = Math.max(1e-9, ...weights.map((w) => Math.abs(w.weight)));

  return (
    <>
      <div className="page-head">
        <h1>Modèle de risque</h1>
        <p>
          Le score de risque combine CVSS, EPSS, CISA KEV et CWE. Le LLM n'intervient jamais
          dans la décision : il ne fait que rédiger l'explication après coup.
        </p>
      </div>

      <div className="stack">
        <section className="card card-pad">
          <h2 className="card-title">
            Moteur actif{" "}
            <span className={`badge ${info.source === "ml" ? "ok" : "warn"}`}>
              {info.source === "ml" ? "Modèle ML entraîné" : "Heuristique de repli"}
            </span>
          </h2>
          <dl className="def-list">
            <dt>Type</dt>
            <dd>{info.model_type}</dd>
            <dt>Description</dt>
            <dd style={{ maxWidth: "75ch" }}>{info.description}</dd>
            {Object.entries(info.metrics || {}).map(([k, v]) => (
              <FragmentRow key={k} k={k} v={v} />
            ))}
          </dl>
        </section>

        <section className="card card-pad">
          <h2 className="card-title">Importance des variables</h2>
          {weights.length === 0 ? (
            <p style={{ color: "var(--muted)", margin: 0 }}>
              Aucun poids disponible : entraînez le modèle (train_risk_model.py) puis rechargez-le
              via POST /api/v1/internal/model/reload.
            </p>
          ) : (
            <div>
              {weights.map((w) => (
                <div key={w.feature} style={{ display: "grid", gridTemplateColumns: "220px 1fr 70px", gap: 12, alignItems: "center", padding: "7px 0", borderBottom: "1px solid var(--line)" }}>
                  <span className="mono" style={{ fontSize: 14 }}>{w.feature}</span>
                  <div className="scorebar"><div className="track">
                    <div className="fill" style={{
                      width: `${(Math.abs(w.weight) / maxWeight) * 100}%`,
                      background: w.weight >= 0 ? "var(--danger)" : "var(--ok)",
                    }} />
                  </div></div>
                  <span className="num" style={{ textAlign: "right" }}>{fmtScore(w.weight, 3)}</span>
                </div>
              ))}
              <p style={{ color: "var(--muted)", fontSize: 13.5, marginBottom: 0 }}>
                Poids positif (rouge) : la variable augmente la probabilité de risque.
                Poids négatif (vert) : elle la diminue.
              </p>
            </div>
          )}
        </section>
      </div>
    </>
  );
}

function FragmentRow({ k, v }) {
  const value = typeof v === "number" ? fmtScore(v, 3) : String(v);
  return (
    <>
      <dt>{k.replaceAll("_", " ")}</dt>
      <dd className="num">{value}</dd>
    </>
  );
}
