import { useEffect, useState, useCallback } from "react";
import Sidebar from "@/components/sentinel/Sidebar";
import HeaderBar from "@/components/sentinel/HeaderBar";
import StatsBar from "@/components/sentinel/StatsBar";
import FleetGrid from "@/components/sentinel/FleetGrid";
import ScannerWidget from "@/components/sentinel/ScannerWidget";
import ThreatLog from "@/components/sentinel/ThreatLog";
import DeviceDetailSheet from "@/components/sentinel/DeviceDetailSheet";
import {
  fetchDevices,
  fetchThreatLogs,
  fetchStats,
} from "@/lib/api";

export default function Dashboard() {
  const [devices, setDevices] = useState([]);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    const [d, l, s] = await Promise.all([
      fetchDevices(),
      fetchThreatLogs(80),
      fetchStats(),
    ]);
    setDevices(d);
    setLogs(l);
    setStats(s);
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
      <Sidebar />
      <main className="flex-1 flex flex-col min-w-0">
        <HeaderBar logs={logs} stats={stats} />
        <StatsBar stats={stats} />
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-3 p-4 auto-rows-min">
          <section className="lg:col-span-8 flex flex-col gap-3 min-w-0">
            <FleetGrid
              devices={devices}
              loading={loading}
              onSelect={setSelectedId}
            />
            <ThreatLog logs={logs} />
          </section>
          <section className="lg:col-span-4 flex flex-col gap-3 min-w-0">
            <ScannerWidget onScanDone={refresh} />
          </section>
        </div>
        <footer className="border-t border-[#222] px-4 py-2 flex items-center justify-between text-[10px] font-mono uppercase tracking-[0.2em] text-[#555]">
          <span>SENTINELGRID v0.1 // UNIVERSAL ENDPOINT THREAT INTELLIGENCE</span>
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
