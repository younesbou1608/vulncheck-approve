import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { api } from "../api/client.js";

const LINKS = [
  { to: "/", label: "Valider un logiciel", glyph: "▶" },
  { to: "/historique", label: "Historique", glyph: "≡" },
  { to: "/cves", label: "Base CVE", glyph: "◆" },
  { to: "/tableau-de-bord", label: "Tableau de bord", glyph: "▤" },
  { to: "/modele", label: "Modèle de risque", glyph: "ƒ" },
];

export default function Sidebar() {
  const [health, setHealth] = useState(null);
  const [down, setDown] = useState(false);

  useEffect(() => {
    let alive = true;
    const load = () =>
      api.health()
        .then((h) => { if (alive) { setHealth(h); setDown(false); } })
        .catch(() => { if (alive) setDown(true); });
    load();
    const timer = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(timer); };
  }, []);

  const tone = down ? "down" : health?.status === "ok" ? "ok" : health ? "degraded" : "";
  const label = down ? "API injoignable" : health ? (health.status === "ok" ? "API opérationnelle" : "API dégradée") : "…";

  return (
    <aside className="sidebar">
      <div className="brand">
        VulnCheck &amp; Approve
        <small>Console sécurité</small>
      </div>
      <nav className="nav" aria-label="Navigation principale">
        {LINKS.map((l) => (
          <NavLink key={l.to} to={l.to} end={l.to === "/"}>
            <span className="glyph" aria-hidden="true">{l.glyph}</span>
            {l.label}
          </NavLink>
        ))}
      </nav>
      <div className="sidebar-footer">
        <div className={`health ${tone}`}>
          <span className="dot" aria-hidden="true" />
          {label}
        </div>
        {health && !down && (
          <div className="health-sub">
            Scoring : {health.risk_engine === "ml" ? "modèle ML" : "heuristique"}
            {" · "}sémantique {health.semantic_matching ? "active" : "inactive"}
            {" · "}LLM {health.llm_configured ? "configuré" : "absent"}
          </div>
        )}
      </div>
    </aside>
  );
}
