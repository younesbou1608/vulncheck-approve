/* États de chargement, d'erreur et de vide, partagés par toutes les pages. */
export function Loading({ label = "Chargement…" }) {
  return (
    <div className="state" role="status">
      <div className="spinner" aria-hidden="true" />
      <p>{label}</p>
    </div>
  );
}

export function ErrorState({ error, retry }) {
  return (
    <div className="state">
      <strong>Impossible de charger les données</strong>
      <p>{error?.message || "Erreur inconnue."}</p>
      {retry && <button className="btn btn-ghost" onClick={retry}>Réessayer</button>}
    </div>
  );
}

export function EmptyState({ title, children }) {
  return (
    <div className="state">
      <strong>{title}</strong>
      <p>{children}</p>
    </div>
  );
}
