import { fmtInt } from "../utils/format.js";

export default function Pagination({ total, limit, offset, onChange }) {
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));
  return (
    <div className="pager">
      <span>{fmtInt(total)} résultats · page {page} / {pages}</span>
      <button className="btn btn-ghost" disabled={offset === 0}
        onClick={() => onChange(Math.max(0, offset - limit))}>← Précédent</button>
      <button className="btn btn-ghost" disabled={offset + limit >= total}
        onClick={() => onChange(offset + limit)}>Suivant →</button>
    </div>
  );
}
