import { verdictInfo } from "../utils/format.js";

export default function VerdictBadge({ verdict }) {
  const { label, tone } = verdictInfo(verdict);
  return <span className={`badge ${tone}`}>{label}</span>;
}
