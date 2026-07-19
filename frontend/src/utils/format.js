/* Formats partagés : dates, pourcentages, libellés de verdicts. */
export const VERDICTS = {
  VALIDE: { label: "Validé", tone: "ok" },
  A_VERIFIER: { label: "À vérifier", tone: "warn" },
  REFUSE: { label: "Refusé", tone: "danger" },
};

export const MATCH_METHODS = {
  alias: "Alias",
  exact: "Exact",
  fuzzy: "Approché",
  semantic: "Sémantique",
  none: "Aucun",
};

export function verdictInfo(verdict) {
  return VERDICTS[verdict] || { label: verdict || "—", tone: "neutral" };
}

export function fmtDate(value, withTime = false) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  const opts = withTime
    ? { dateStyle: "medium", timeStyle: "short" }
    : { dateStyle: "medium" };
  return new Intl.DateTimeFormat("fr-FR", opts).format(d);
}

export function fmtPercent(value, digits = 0) {
  if (value === null || value === undefined) return "—";
  return `${(value * 100).toFixed(digits)} %`;
}

export function fmtScore(value, digits = 2) {
  if (value === null || value === undefined) return "—";
  return Number(value).toFixed(digits);
}

export function fmtInt(value) {
  if (value === null || value === undefined) return "—";
  return new Intl.NumberFormat("fr-FR").format(value);
}

/* Couleur d'un score 0-1 (risque, CVSS/10) : vert -> ambre -> rouge. */
export function scoreColor(ratio) {
  if (ratio === null || ratio === undefined) return "var(--line-strong)";
  if (ratio >= 0.7) return "var(--danger)";
  if (ratio >= 0.35) return "var(--warn)";
  return "var(--ok)";
}

export function severityTone(severity) {
  const s = (severity || "").toUpperCase();
  if (s === "CRITICAL" || s === "HIGH") return "danger";
  if (s === "MEDIUM") return "warn";
  if (s === "LOW" || s === "NONE") return "ok";
  return "neutral";
}
