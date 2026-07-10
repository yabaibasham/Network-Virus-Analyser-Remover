import { useEffect, useState, useCallback } from "react";
import Sidebar from "@/components/sentinel/Sidebar";
import HeaderBar from "@/components/sentinel/HeaderBar";
import StatsBar from "@/components/sentinel/StatsBar";
import FleetGrid from "@/components/sentinel/FleetGrid";
import ScannerWidget from "@/components/sentinel/ScannerWidget";
import ThreatLog from "@/components/sentinel/ThreatLog";
import DeviceDetailSheet from "@/components/sentinel/DeviceDetailSheet";
import RecoveryPanel from "@/components/sentinel/RecoveryPanel";
import IncidentsPanel from "@/components/sentinel/IncidentsPanel";
import NetworkMap from "@/components/sentinel/NetworkMap";
import CommunityWatch from "@/components/sentinel/CommunityWatch";
import FraudBoard from "@/components/sentinel/FraudBoard";
import RemediationConsole from "@/components/sentinel/RemediationConsole";
import {
  fetchDevices,
  fetchThreatLogs,
  fetchStats,
  fetchIncidents,
} from "@/lib/api";

const VIEW_TITLE = {
  overview: "OPERATIONS OVERVIEW",
  network: "LAN / WAN NETWORK MAP",
  community: "NEIGHBOURHOOD WATCH",
  remediation: "REMEDIATION CONSOLE",
};

export default function Dashboard() {
  const [devices, setDevices] = useState([]);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState("overview");

  const refresh = useCallback(async () => {
    const [d, l, s, inc] = await Promise.all([
      fetchDevices(),
      fetchThreatLogs(80),
      fetchStats(),
      fetchIncidents(50),
    ]);
    setDevices(d);
    setLogs(l);
    setStats(s);
    setIncidents(inc);
    setLoading(false);
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 12000);
    return () => clearInterval(t);
  }, [refresh]);

  return (
    <div
      className="min-h-screen flex bg-[#050505] text-white relative"
      data-testid="dashboard-root"
    >
      <Sidebar view={view} setView={setView} />
      <main className="flex-1 flex flex-col min-w-0">
        <HeaderBar logs={logs} stats={stats} />
        <StatsBar stats={stats} />

        <div className="flex items-center gap-3 px-4 py-2 border-b border-[#222] bg-[#0a0a0a]">
          <span className="text-[10px] font-mono uppercase tracking-[0.25em] text-[#666]">
            // {VIEW_TITLE[view]}
          </span>
        </div>

        <div className="flex-1 p-4">
          {view === "overview" && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 auto-rows-min">
              <section className="lg:col-span-8 flex flex-col gap-3 min-w-0">
                <FleetGrid devices={devices} loading={loading} onSelect={setSelectedId} />
                <IncidentsPanel incidents={incidents} onChanged={refresh} />
                <ThreatLog logs={logs} />
              </section>
              <section className="lg:col-span-4 flex flex-col gap-3 min-w-0">
                <ScannerWidget onScanDone={refresh} vtEnabled={stats?.vt_enabled} />
                <RecoveryPanel devices={devices} onChanged={refresh} />
              </section>
            </div>
          )}

          {view === "network" && <NetworkMap onSelect={setSelectedId} />}

          {view === "community" && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 items-start">
              <CommunityWatch />
              <FraudBoard />
            </div>
          )}

          {view === "remediation" && (
            <RemediationConsole onSelect={setSelectedId} onChanged={refresh} />
          )}
        </div>

        <footer className="border-t border-[#222] px-4 py-2 flex items-center justify-between text-[10px] font-mono uppercase tracking-[0.2em] text-[#555]">
          <span>SENTINELGRID v0.3 // UNIVERSAL ENDPOINT THREAT INTELLIGENCE</span>
          <span className="flex items-center gap-2">
            <span className="status-dot" style={{ background: "#00F5A0" }} />
            UPLINK NOMINAL
          </span>
        </footer>
      </main>
      <DeviceDetailSheet
        deviceId={selectedId}
        onClose={() => setSelectedId(null)}
        onChanged={refresh}
      />
    </div>
  );
}
