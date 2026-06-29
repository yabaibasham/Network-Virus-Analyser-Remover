const KPI = ({ label, value, accent, testid }) => (
  <div
    className="flex-1 min-w-0 border-r border-[#222] last:border-r-0 px-4 py-3"
    data-testid={testid}
  >
    <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
      {label}
    </div>
    <div
      className="font-display font-bold text-2xl mt-1 leading-none"
      style={{ color: accent || "#fff" }}
    >
      {value ?? "—"}
    </div>
  </div>
);

export default function StatsBar({ stats }) {
  return (
    <div
      className="flex border-b border-[#222] bg-[#0a0a0a]"
      data-testid="stats-bar"
    >
      <KPI label="DEVICES MONITORED" value={stats?.devices_total} testid="kpi-total" />
      <KPI
        label="CLEAN"
        value={stats?.devices_clean}
        accent="#0044FF"
        testid="kpi-clean"
      />
      <KPI
        label="INFECTED"
        value={stats?.devices_infected}
        accent="#FF3B30"
        testid="kpi-infected"
      />
      <KPI
        label="QUARANTINED"
        value={stats?.devices_quarantined}
        accent="#FFCC00"
        testid="kpi-quarantined"
      />
      <KPI
        label="SCANS RUN"
        value={stats?.scans_performed}
        testid="kpi-scans"
      />
      <KPI
        label="THREATS NEUTRALIZED"
        value={stats?.threats_neutralized}
        accent="#00F5A0"
        testid="kpi-threats"
      />
      <KPI
        label="SURFACE COVERAGE"
        value={stats ? `${stats.surface_coverage_pct}%` : "—"}
        testid="kpi-coverage"
      />
    </div>
  );
}
