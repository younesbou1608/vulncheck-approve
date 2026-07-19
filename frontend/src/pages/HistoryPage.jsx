import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client.js";
import VerdictBadge from "../components/VerdictBadge.jsx";
import ScoreBar from "../components/ScoreBar.jsx";
import Pagination from "../components/Pagination.jsx";
import { EmptyState, ErrorState, Loading } from "../components/DataStates.jsx";
import { MATCH_METHODS, fmtDate, fmtScore } from "../utils/format.js";

const LIMIT = 20;

export default function HistoryPage() {
  const [page, setPage] = useState({ items: [], total: 0 });
  const [offset, setOffset] = useState(0);
  const [verdict, setVerdict] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const load = () => {
    setLoading(true);
    setError(null);
    api.listValidations({ limit: LIMIT, offset, verdict })
      .then(setPage)
      .catch(setError)
      .finally(() => setLoading(false));
  };
  useEffect(load, [offset, verdict]);

  return (
    <>
      <div className="page-head">
        <h1>Historique des validations</h1>
        <p>Toutes les demandes traitées, du plus récent au plus ancien. Cliquez sur une ligne pour rouvrir le rapport complet.</p>
      </div>

      <div className="toolbar">
        <div className="field">
          <label htmlFor="verdict-filter">Filtrer par verdict</label>
          <select id="verdict-filter" value={verdict}
            onChange={(e) => { setVerdict(e.target.value); setOffset(0); }}>
            <option value="">Tous les verdicts</option>
            <option value="VALIDE">Validé</option>
            <option value="A_VERIFIER">À vérifier</option>
            <option value="REFUSE">Refusé</option>
          </select>
        </div>
      </div>

      <div className="card">
        {loading ? <Loading /> : error ? <ErrorState error={error} retry={load} /> : !page.items.length ? (
          <EmptyState title="Aucune validation">
            Lancez une première validation depuis l'écran « Valider un logiciel ».
          </EmptyState>
        ) : (
          <>
            <table className="table">
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Logiciel</th>
                  <th>Produit identifié</th>
                  <th>Matching</th>
                  <th>Confiance</th>
                  <th>Risque</th>
                  <th>CVE</th>
                  <th>KEV</th>
                  <th>Verdict</th>
                </tr>
              </thead>
              <tbody>
                {page.items.map((v) => (
                  <tr key={v.id} className="clickable" tabIndex={0}
                    onClick={() => navigate(`/historique/${v.id}`)}
                    onKeyDown={(e) => e.key === "Enter" && navigate(`/historique/${v.id}`)}>
                    <td className="num" style={{ whiteSpace: "nowrap" }}>{fmtDate(v.created_at, true)}</td>
                    <td>
                      <strong>{v.software_name}</strong>
                      {v.software_version && <span className="mono"> {v.software_version}</span>}
                    </td>
                    <td className="mono">
                      {v.matched_product
                        ? `${v.matched_vendor ? v.matched_vendor + " / " : ""}${v.matched_product}` : "—"}
                    </td>
                    <td>{MATCH_METHODS[v.match_method] || v.match_method}</td>
                    <td><ScoreBar value={v.match_confidence} /></td>
                    <td><ScoreBar value={v.risk_score} /></td>
                    <td className="num">{v.cve_count}</td>
                    <td className="num" style={{ color: v.kev_count > 0 ? "var(--danger)" : undefined }}>
                      {v.kev_count}
                    </td>
                    <td><VerdictBadge verdict={v.verdict} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination total={page.total} limit={LIMIT} offset={offset} onChange={setOffset} />
          </>
        )}
      </div>
    </>
  );
}
