import { Link } from "react-router-dom";
import DecisionMatrix from "./DecisionMatrix.jsx";
import ScoreBar from "./ScoreBar.jsx";
import {
  MATCH_METHODS,
  fmtDate,
  fmtPercent,
  fmtScore,
  scoreColor,
  severityTone,
  verdictInfo,
} from "../utils/format.js";

/* Rapport complet d'une validation : verdict, matching, CVE, explication.
   Utilisé par la page de validation et par le détail d'historique. */
export default function ValidationReport({ report }) {
  const verdict = verdictInfo(report.verdict);
  const matched = report.matched_product
    ? `${report.matched_vendor ? report.matched_vendor + " / " : ""}${report.matched_product}`
    : "Aucun produit CPE identifié";

  return (
    <div className="stack">
      {/* --- Bandeau verdict (élément signature) --- */}
      <section className={`card verdict-panel ${report.verdict}`} aria-live="polite">
        <div className="verdict-spine" aria-hidden="true" />
        <div className="verdict-body">
          <div>
            <div className="verdict-eyebrow">
              Verdict · {report.software_name}
              {report.software_version ? ` ${report.software_version}` : " (toutes versions)"}
            </div>
            <div className="verdict-word">{verdict.label}</div>
            {report.decision_reason && (
              <p className="verdict-reason">{report.decision_reason}</p>
            )}
          </div>
          <div className="verdict-meta">
            <div className="meta-item">
              <div className="k">Produit identifié</div>
              <div className="v mono">{matched}</div>
            </div>
            <div className="meta-item">
              <div className="k">Méthode de matching</div>
              <div className="v">{MATCH_METHODS[report.match_method] || report.match_method}</div>
            </div>
            <div className="meta-item">
              <div className="k">Confiance</div>
              <div className="v num">{fmtPercent(report.match_confidence)}</div>
            </div>
            <div className="meta-item">
              <div className="k">Risque agrégé</div>
              <div className="v num" style={{ color: scoreColor(report.risk_score) }}>
                {report.risk_score == null ? "—" : fmtPercent(report.risk_score)}
                {report.risk_model ? ` (${report.risk_model === "ml" ? "ML" : "heuristique"})` : ""}
              </div>
            </div>
            <div className="meta-item">
              <div className="k">CVE applicables</div>
              <div className="v num">{report.cve_count}</div>
            </div>
            <div className="meta-item">
              <div className="k">Dont CISA KEV</div>
              <div className="v num" style={{ color: report.kev_count > 0 ? "var(--danger)" : undefined }}>
                {report.kev_count}
              </div>
            </div>
          </div>
          <DecisionMatrix risk={report.risk_score} confidence={report.match_confidence} />
        </div>
      </section>

      {/* --- Remédiation : versions sûres --- */}
      {(report.recommended_version || report.fixed_versions?.length > 0) && (
        <section className="card card-pad" style={{ borderLeft: "5px solid var(--accent)" }}>
          <h2 className="card-title">Remédiation</h2>
          {report.recommended_version && (
            <p style={{ margin: "0 0 12px", fontSize: 17 }}>
              Version sûre recommandée :{" "}
              <strong className="mono" style={{ color: "var(--accent-ink)", fontSize: 18 }}>
                {report.recommended_version}
              </strong>
              {" "}— corrige l'ensemble des CVE retenues
              {report.verdict === "REFUSE" && " (cette version serait acceptable à la place)"}
              .
            </p>
          )}
          {report.fixed_versions?.length > 0 && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {report.fixed_versions.slice(0, 12).map((f) => (
                <span key={f.cve_id} className="badge neutral">
                  {f.cve_id} → {f.fixed_in}
                </span>
              ))}
              {report.fixed_versions.length > 12 && (
                <span className="badge neutral">+{report.fixed_versions.length - 12} autres</span>
              )}
            </div>
          )}
          {report.unfixed_cve_count > 0 && (
            <p style={{ margin: "12px 0 0", color: "var(--warn)", fontSize: 14.5 }}>
              {report.unfixed_cve_count} CVE sans correctif connu dans le NVD : prévoir des
              mesures compensatoires si l'installation est indispensable.
            </p>
          )}
        </section>
      )}

      {/* --- Explication --- */}
      {report.explanation && (
        <section className="card card-pad">
          <h2 className="card-title">
            Analyse{" "}
            <span className="badge neutral">
              {report.explanation_source === "llm" ? "générée par LLM (non décisionnaire)" : "gabarit déterministe"}
            </span>
          </h2>
          <p style={{ margin: 0, maxWidth: "80ch", whiteSpace: "pre-line" }}>{report.explanation}</p>
        </section>
      )}

      {/* --- Autres candidats --- */}
      {report.alternatives?.length > 0 && (
        <section className="card card-pad">
          <h2 className="card-title">Autres candidats envisagés</h2>
          <table className="table">
            <thead>
              <tr><th>Éditeur</th><th>Produit</th><th>Confiance</th></tr>
            </thead>
            <tbody>
              {report.alternatives.map((a, i) => (
                <tr key={i}>
                  <td className="mono">{a.vendor || "—"}</td>
                  <td className="mono">{a.product}</td>
                  <td><ScoreBar value={a.confidence} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {/* --- CVE applicables --- */}
      <section className="card">
        <div className="card-pad" style={{ paddingBottom: 0 }}>
          <h2 className="card-title">
            CVE applicables ({report.cves?.length || 0}
            {report.cve_count > (report.cves?.length || 0) ? ` affichées sur ${report.cve_count}` : ""})
          </h2>
        </div>
        {report.cves?.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>CVE</th>
                <th>Sévérité</th>
                <th>CVSS</th>
                <th>EPSS</th>
                <th>Risque prédit</th>
                <th>Publication</th>
              </tr>
            </thead>
            <tbody>
              {report.cves.map((c) => (
                <tr key={c.cve_id}>
                  <td>
                    <Link className="mono" to={`/cves/${c.cve_id}`}>{c.cve_id}</Link>
                    {c.in_kev && <span className="badge kev" style={{ marginLeft: 8 }}>KEV</span>}
                  </td>
                  <td>
                    <span className={`badge ${severityTone(c.base_severity)}`}>
                      {c.base_severity || "N/A"}
                    </span>
                  </td>
                  <td className="num">{fmtScore(c.base_score, 1)}</td>
                  <td className="num">{c.epss == null ? "—" : fmtPercent(c.epss, 1)}</td>
                  <td><ScoreBar value={c.risk_score} /></td>
                  <td className="num">{fmtDate(c.published)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="state">
            <strong>Aucune CVE applicable</strong>
            <p>Aucune vulnérabilité connue ne couvre cette version dans la base locale.</p>
          </div>
        )}
      </section>

      <p style={{ color: "var(--muted)", fontSize: 14 }}>
        Traitement en {report.duration_ms} ms
        {report.created_at ? ` · archivé le ${fmtDate(report.created_at, true)}` : ""}
        {report.id ? ` · référence #${report.id}` : ""}
      </p>
    </div>
  );
}
