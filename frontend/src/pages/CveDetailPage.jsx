import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client.js";
import { ErrorState, Loading } from "../components/DataStates.jsx";
import { fmtDate, fmtPercent, fmtScore, severityTone } from "../utils/format.js";

export default function CveDetailPage() {
  const { cveId } = useParams();
  const [cve, setCve] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setCve(null);
    setError(null);
    api.getCve(cveId).then(setCve).catch(setError);
  }, [cveId]);

  if (error) return <ErrorState error={error} />;
  if (!cve) return <Loading />;

  return (
    <>
      <div className="page-head">
        <h1 className="mono" style={{ fontFamily: "var(--font-mono)" }}>{cve.cve_id}</h1>
        <p>
          <span className={`badge ${severityTone(cve.base_severity)}`}>{cve.base_severity || "N/A"}</span>
          {cve.in_kev && <span className="badge kev" style={{ marginLeft: 8 }}>CISA KEV — exploitation confirmée</span>}
        </p>
      </div>

      <div className="stack">
        <section className="card card-pad">
          <h2 className="card-title">Description</h2>
          <p style={{ margin: 0, maxWidth: "85ch" }}>{cve.description_en || "Aucune description disponible."}</p>
        </section>

        <section className="card card-pad">
          <h2 className="card-title">Signaux de risque</h2>
          <dl className="def-list">
            <dt>Score CVSS</dt>
            <dd className="num">
              {fmtScore(cve.base_score, 1)}
              {cve.cvss_version ? ` (v${cve.cvss_version})` : ""}
              {cve.vector_string && <div className="mono" style={{ color: "var(--muted)", fontSize: 13 }}>{cve.vector_string}</div>}
            </dd>
            <dt>EPSS</dt>
            <dd className="num">
              {cve.epss == null ? "—" : `${fmtPercent(cve.epss, 2)} de probabilité d'exploitation à 30 jours`}
              {cve.epss_percentile != null && ` (percentile ${fmtPercent(cve.epss_percentile)})`}
            </dd>
            <dt>CISA KEV</dt>
            <dd>
              {cve.in_kev
                ? `Oui — ajoutée le ${fmtDate(cve.kev_date_added)}${cve.known_ransomware_use === "Known" ? ", usage rançongiciel connu" : ""}`
                : "Non répertoriée"}
            </dd>
            <dt>Faiblesses (CWE)</dt>
            <dd className="mono">{cve.cwe_ids?.length ? cve.cwe_ids.join(", ") : "—"}</dd>
            <dt>Publication</dt>
            <dd className="num">{fmtDate(cve.published)}</dd>
            <dt>Statut NVD</dt>
            <dd>{cve.vuln_status || "—"}</dd>
            <dt>Références</dt>
            <dd className="num">{cve.ref_count}</dd>
          </dl>
        </section>

        {cve.configurations?.length > 0 && (
          <section className="card">
            <div className="card-pad" style={{ paddingBottom: 0 }}>
              <h2 className="card-title">Configurations affectées ({cve.configurations.length} max. affichées)</h2>
            </div>
            <table className="table">
              <thead>
                <tr><th>Éditeur</th><th>Produit</th><th>Version / plage</th></tr>
              </thead>
              <tbody>
                {cve.configurations.map((cfg, i) => (
                  <tr key={i}>
                    <td className="mono">{cfg.vendor || "—"}</td>
                    <td className="mono">{cfg.product || "—"}</td>
                    <td className="mono">{describeRange(cfg)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        )}

        {cve.references?.length > 0 && (
          <section className="card card-pad">
            <h2 className="card-title">Références ({cve.references.length} max. affichées)</h2>
            <ul style={{ margin: 0, paddingLeft: 20, lineHeight: 1.9 }}>
              {cve.references.map((r, i) => (
                <li key={i}>
                  <a href={r.url} target="_blank" rel="noreferrer" className="mono" style={{ fontSize: 14, wordBreak: "break-all" }}>
                    {r.url}
                  </a>
                  {r.source && <span style={{ color: "var(--muted)", fontSize: 13 }}> — {r.source}</span>}
                </li>
              ))}
            </ul>
          </section>
        )}

        <p><Link to="/cves">← Retour à la recherche</Link></p>
      </div>
    </>
  );
}

function describeRange(cfg) {
  if (cfg.version && cfg.version !== "*" && cfg.version !== "-") return cfg.version;
  const parts = [];
  if (cfg.version_start_including) parts.push(`≥ ${cfg.version_start_including}`);
  if (cfg.version_start_excluding) parts.push(`> ${cfg.version_start_excluding}`);
  if (cfg.version_end_including) parts.push(`≤ ${cfg.version_end_including}`);
  if (cfg.version_end_excluding) parts.push(`< ${cfg.version_end_excluding}`);
  return parts.length ? parts.join(" et ") : "toutes versions";
}
