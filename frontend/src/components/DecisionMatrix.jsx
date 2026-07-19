/* Élément signature : matrice de décision risque x confiance.
   Reproduit visuellement la règle métier (§3.4) et positionne la
   validation courante dessus. Seuils par défaut du backend :
   risque 0,35 / 0,70 - confiance 0,50 (min) / 0,75. */
const W = 190;
const H = 150;
const PAD = { left: 34, bottom: 30, top: 8, right: 8 };
const RISK_HIGH = 0.7;
const RISK_LOW = 0.35;
const CONF_HIGH = 0.75;
const CONF_MIN = 0.5;

const plotW = W - PAD.left - PAD.right;
const plotH = H - PAD.top - PAD.bottom;
const x = (conf) => PAD.left + conf * plotW;
const y = (risk) => PAD.top + (1 - risk) * plotH;

export default function DecisionMatrix({ risk, confidence }) {
  const hasPoint = risk !== null && risk !== undefined && confidence !== null && confidence !== undefined;
  return (
    <div className="matrix-wrap">
      <svg width={W} height={H} role="img"
        aria-label="Position de la validation dans la matrice risque-confiance">
        {/* Zones de décision */}
        <rect x={x(0)} y={y(1)} width={plotW} height={y(RISK_HIGH) - y(1)}
          fill="var(--danger-soft)" />
        <rect x={x(0)} y={y(RISK_HIGH)} width={plotW} height={y(RISK_LOW) - y(RISK_HIGH)}
          fill="var(--warn-soft)" />
        <rect x={x(0)} y={y(RISK_LOW)} width={x(CONF_HIGH) - x(0)} height={y(0) - y(RISK_LOW)}
          fill="var(--warn-soft)" />
        <rect x={x(CONF_HIGH)} y={y(RISK_LOW)} width={x(1) - x(CONF_HIGH)} height={y(0) - y(RISK_LOW)}
          fill="var(--ok-soft)" />
        {/* Sous la confiance minimale : jamais de décision automatique */}
        <rect x={x(0)} y={y(1)} width={x(CONF_MIN) - x(0)} height={y(0) - y(1)}
          fill="url(#hatch)" opacity="0.5" />
        <defs>
          <pattern id="hatch" width="6" height="6" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
            <line x1="0" y1="0" x2="0" y2="6" stroke="var(--line-strong)" strokeWidth="2" />
          </pattern>
        </defs>
        {/* Axes */}
        <line x1={x(0)} y1={y(0)} x2={x(1)} y2={y(0)} stroke="var(--ink-soft)" strokeWidth="1.5" />
        <line x1={x(0)} y1={y(0)} x2={x(0)} y2={y(1)} stroke="var(--ink-soft)" strokeWidth="1.5" />
        <text x={x(0.5)} y={H - 6} textAnchor="middle" fontSize="11" fill="var(--muted)">confiance →</text>
        <text x={12} y={y(0.5)} textAnchor="middle" fontSize="11" fill="var(--muted)"
          transform={`rotate(-90 12 ${y(0.5)})`}>risque →</text>
        {/* Point de la validation courante */}
        {hasPoint && (
          <>
            <circle cx={x(Math.min(1, confidence))} cy={y(Math.min(1, risk))} r="9"
              fill="none" stroke="var(--ink)" strokeWidth="1.5" opacity="0.35" />
            <circle cx={x(Math.min(1, confidence))} cy={y(Math.min(1, risk))} r="4.5" fill="var(--ink)" />
          </>
        )}
      </svg>
      <div className="matrix-caption">
        Matrice de décision risque × confiance (seuils par défaut)
      </div>
    </div>
  );
}
