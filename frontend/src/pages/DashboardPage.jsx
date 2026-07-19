import { useEffect, useMemo, useState } from "react";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend,
  Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { api } from "../api/client.js";
import { ErrorState, Loading } from "../components/DataStates.jsx";
import { VERDICTS, fmtDate, fmtInt } from "../utils/format.js";

const VERDICT_COLORS = { VALIDE: "#157f3d", A_VERIFIER: "#d97a12", REFUSE: "#b42323" };

export default function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [error, setError] = useState(null);

  const load = () => {
    setError(null);
    api.statsOverview().then(setStats).catch(setError);
  };
  useEffect(load, []);

  /* {day, verdict, total}[] -> une ligne par jour avec un champ par verdict */
  const byDay = useMemo(() => {
    if (!stats) return [];
    const days = new Map();
    for (const p of stats.validations_by_day) {
      if (!days.has(p.day)) days.set(p.day, { day: p.day });
      days.get(p.day)[p.verdict] = p.total;
    }
    return [...days.values()];
  }, [stats]);

  const verdictPie = useMemo(() => {
    if (!stats) return [];
    return Object.entries(stats.verdicts).map(([verdict, total]) => ({
      name: VERDICTS[verdict]?.label || verdict, verdict, total,
    }));
  }, [stats]);

  if (error) return <ErrorState error={error} retry={load} />;
  if (!stats) return <Loading />;

  const shortDay = (d) => new Date(d).toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" });
  const shortMonth = (d) => new Date(d).toLocaleDateString("fr-FR", { month: "short", year: "2-digit" });

  return (
    <>
      <div className="page-head">
        <h1>Tableau de bord</h1>
        <p>Volumétrie de la base de connaissance, fraîcheur des synchronisations Airflow et activité de validation.</p>
      </div>

      <div className="stat-grid">
        <StatCard label="CVE en base" value={stats.cve_total}
          sub={`Dernière modification : ${fmtDate(stats.last_cve_modified, true)}`} />
        <StatCard label="Entrées CISA KEV" value={stats.kev_total}
          sub={`Synchronisé : ${fmtDate(stats.kev_last_sync, true)}`} />
        <StatCard label="Scores EPSS" value={stats.epss_total}
          sub={`Synchronisé : ${fmtDate(stats.epss_last_sync, true)}`} />
        <StatCard label="Embeddings produits" value={stats.embeddings_total}
          sub="Matching sémantique" />
        <StatCard label="Validations traitées" value={stats.validation_total}
          sub="Depuis la mise en service" />
      </div>

      <div className="chart-grid" style={{ marginTop: 20 }}>
        <section className="card card-pad">
          <h2 className="card-title">Validations des 30 derniers jours</h2>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={byDay}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" />
              <XAxis dataKey="day" tickFormatter={shortDay} fontSize={12} />
              <YAxis allowDecimals={false} fontSize={12} />
              <Tooltip labelFormatter={(d) => fmtDate(d)} />
              <Legend />
              <Bar dataKey="VALIDE" name="Validé" stackId="v" fill={VERDICT_COLORS.VALIDE} />
              <Bar dataKey="A_VERIFIER" name="À vérifier" stackId="v" fill={VERDICT_COLORS.A_VERIFIER} />
              <Bar dataKey="REFUSE" name="Refusé" stackId="v" fill={VERDICT_COLORS.REFUSE} />
            </BarChart>
          </ResponsiveContainer>
        </section>

        <section className="card card-pad">
          <h2 className="card-title">Répartition des verdicts</h2>
          {verdictPie.length === 0 ? (
            <p style={{ color: "var(--muted)" }}>Aucune validation pour le moment.</p>
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie data={verdictPie} dataKey="total" nameKey="name"
                  innerRadius={60} outerRadius={95} paddingAngle={2}>
                  {verdictPie.map((entry) => (
                    <Cell key={entry.verdict} fill={VERDICT_COLORS[entry.verdict] || "#64748f"} />
                  ))}
                </Pie>
                <Tooltip formatter={(v) => fmtInt(v)} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          )}
        </section>

        <section className="card card-pad">
          <h2 className="card-title">CVE publiées par mois (24 mois)</h2>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={stats.cves_by_month}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" />
              <XAxis dataKey="month" tickFormatter={shortMonth} fontSize={12} />
              <YAxis fontSize={12} />
              <Tooltip labelFormatter={(d) => shortMonth(d)} formatter={(v) => [fmtInt(v), "CVE"]} />
              <Area type="monotone" dataKey="total" stroke="#2447c5" fill="#e7ecfb" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </section>

        <section className="card card-pad">
          <h2 className="card-title">Distribution de la confiance de matching</h2>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={stats.confidence_distribution}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" />
              <XAxis dataKey="bucket_min" fontSize={12}
                tickFormatter={(v) => `${Math.round(v * 100)}%`} />
              <YAxis allowDecimals={false} fontSize={12} />
              <Tooltip
                labelFormatter={(v) => `Confiance ${Math.round(v * 100)}–${Math.round(v * 100) + 10} %`}
                formatter={(v) => [fmtInt(v), "validations"]} />
              <Bar dataKey="total" fill="#2447c5" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </section>
      </div>
    </>
  );
}

function StatCard({ label, value, sub }) {
  return (
    <div className="card stat">
      <div className="label">{label}</div>
      <div className="value">{fmtInt(value)}</div>
      {sub && <div className="sub">{sub}</div>}
    </div>
  );
}
