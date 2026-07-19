import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client.js";
import { EmptyState, ErrorState, Loading } from "../components/DataStates.jsx";
import { fmtDate, fmtScore, severityTone } from "../utils/format.js";

/* Recherche libre dans la base CVE locale (identifiant ou mot-clé). */
export default function CvesPage() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const search = (e) => {
    e.preventDefault();
    const q = query.trim();
    if (q.length < 3 || loading) return;
    setLoading(true);
    setError(null);
    api.searchCves(q, 30)
      .then(setResults)
      .catch(setError)
      .finally(() => setLoading(false));
  };

  return (
    <>
      <div className="page-head">
        <h1>Base CVE locale</h1>
        <p>Recherchez par identifiant (« CVE-2021-44228 ») ou par mot-clé de description (« log4j »). Minimum 3 caractères.</p>
      </div>

      <form className="card card-pad toolbar" onSubmit={search} style={{ marginBottom: 20 }}>
        <div className="field" style={{ flex: 1 }}>
          <label htmlFor="cve-query">Identifiant ou mot-clé</label>
          <input id="cve-query" type="search" value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="CVE-2021-44228, openssl, ransomware…" minLength={3} maxLength={100} />
        </div>
        <button className="btn" type="submit" disabled={loading || query.trim().length < 3}>
          {loading ? "Recherche…" : "Rechercher"}
        </button>
      </form>

      {loading && <Loading />}
      {error && <ErrorState error={error} />}
      {results && !loading && (
        <div className="card">
          {results.length === 0 ? (
            <EmptyState title="Aucun résultat">
              Aucune CVE de la base locale ne correspond à « {query.trim()} ».
            </EmptyState>
          ) : (
            <table className="table">
              <thead>
                <tr><th>CVE</th><th>Sévérité</th><th>CVSS</th><th>Publication</th><th>Description</th></tr>
              </thead>
              <tbody>
                {results.map((c) => (
                  <tr key={c.cve_id} className="clickable" tabIndex={0}
                    onClick={() => navigate(`/cves/${c.cve_id}`)}
                    onKeyDown={(e) => e.key === "Enter" && navigate(`/cves/${c.cve_id}`)}>
                    <td className="mono" style={{ whiteSpace: "nowrap" }}>{c.cve_id}</td>
                    <td><span className={`badge ${severityTone(c.base_severity)}`}>{c.base_severity || "N/A"}</span></td>
                    <td className="num">{fmtScore(c.base_score, 1)}</td>
                    <td className="num" style={{ whiteSpace: "nowrap" }}>{fmtDate(c.published)}</td>
                    <td style={{ color: "var(--ink-soft)", maxWidth: 520 }}>
                      {(c.description_en || "").slice(0, 180)}
                      {(c.description_en || "").length > 180 ? "…" : ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </>
  );
}
