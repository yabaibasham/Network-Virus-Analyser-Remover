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
import OrgOnboarding from "@/components/sentinel/OrgOnboarding";
import MembersDialog from "@/components/sentinel/MembersDialog";
import {
  fetchDevices,
  fetchThreatLogs,
  fetchStats,
  fetchIncidents,
  fetchMyOrgs,
  switchOrg,
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

  const [orgState, setOrgState] = useState(null); // {orgs, active_org_id, superadmin, user}
  const [orgStatus, setOrgStatus] = useState("loading"); // loading | none | ready
  const [creatingOrg, setCreatingOrg] = useState(false);
  const [membersOpen, setMembersOpen] = useState(false);

  const loadOrgs = useCallback(async () => {
    try {
      let info = await fetchMyOrgs();
      if (!info.orgs.length) {
        setOrgState(info);
        setOrgStatus("none");
        return;
      }
      const activeValid = info.orgs.some((o) => o.org_id === info.active_org_id);
      if (!activeValid) {
        await switchOrg(info.orgs[0].org_id);
        info = await fetchMyOrgs();
      }
      setOrgState(info);
      setOrgStatus("ready");
    } catch {
      /* 401 redirect handled globally */
    }
  }, []);

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
    loadOrgs();
  }, [loadOrgs]);

  useEffect(() => {
    if (orgStatus !== "ready") return;
    refresh();
    const t = setInterval(refresh, 12000);
    return () => clearInterval(t);
  }, [orgStatus, refresh]);

  if (orgStatus === "loading") {
    return (
      <div
        className="min-h-screen flex items-center justify-center bg-[#050505] text-white"
        data-testid="org-loading"
      >
        <div className="font-mono text-sm text-[#888] flex items-center gap-3">
          <span className="w-2.5 h-2.5 rounded-full bg-[#00F5A0] animate-pulse" />
          Loading organisation…
        </div>
      </div>
    );
  }

  if (orgStatus === "none" || creatingOrg) {
    return (
      <OrgOnboarding
        user={orgState?.user}
        onCancel={creatingOrg ? () => setCreatingOrg(false) : undefined}
        onCreated={() => {
          setCreatingOrg(false);
          window.location.reload();
        }}
      />
    );
  }

  const activeRole =
    orgState?.orgs.find((o) => o.org_id === orgState.active_org_id)?.role ||
    (orgState?.superadmin ? "owner" : null);

  return (
    <div
      className="min-h-screen flex bg-[#050505] text-white relative"
      data-testid="dashboard-root"
    >
      <Sidebar view={view} setView={setView} />
      <main className="flex-1 flex flex-col min-w-0">
        <HeaderBar
          logs={logs}
          stats={stats}
          user={orgState?.user}
          orgs={orgState?.orgs}
          activeOrgId={orgState?.active_org_id}
          role={activeRole}
          superadmin={orgState?.superadmin}
          onManageMembers={() => setMembersOpen(true)}
          onNewOrg={() => setCreatingOrg(true)}
        />
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
      <MembersDialog
        open={membersOpen}
        onOpenChange={setMembersOpen}
        currentUserId={orgState?.user?.user_id}
      />
    </div>
  );
}
