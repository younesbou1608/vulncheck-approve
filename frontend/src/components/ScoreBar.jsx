import { fmtPercent, scoreColor } from "../utils/format.js";

/* Barre de score 0-1 avec valeur lisible (risque, confiance...). */
export default function ScoreBar({ value, invert = false }) {
  if (value === null || value === undefined) {
    return <span className="mono">—</span>;
  }
  const ratio = Math.max(0, Math.min(1, value));
  const color = invert ? scoreColor(1 - ratio) : scoreColor(ratio);
  return (
    <div className="scorebar">
      <div className="track">
        <div className="fill" style={{ width: `${ratio * 100}%`, background: color }} />
      </div>
      <span className="val">{fmtPercent(ratio)}</span>
    </div>
  );
}
