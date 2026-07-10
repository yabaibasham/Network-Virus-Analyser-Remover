import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  ShieldAlert,
  Activity,
  Cpu,
  Crosshair,
  RadioTower,
  Car,
  Camera,
  Server,
  MapPin,
  ArrowRight,
  Zap,
  Layers,
  Sparkles,
} from "lucide-react";
import { fetchStats } from "@/lib/api";

const PILLARS = [
  {
    Icon: Crosshair,
    title: "DEEP SURFACE",
    body: "Memory map, process tree, kernel hooks, persistence anchors, firmware attestation, C2 beacon heuristics — all flattened into one tactical view.",
  },
  {
    Icon: Layers,
    title: "EVERY DEVICE",
    body: "Linux, Windows, macOS, iOS, Android, IP cameras, Tesla, IoT sensors, routers, Raspberry Pi. One uniform schema, ten device classes.",
  },
  {
    Icon: Sparkles,
    title: "AI HEURISTIC",
    body: "Static IOC matcher composes verdicts with Claude Sonnet 4.6 reasoning — risk score 0-100, IOC list, recommended actions, sub-second.",
  },
  {
    Icon: MapPin,
    title: "RECOVERY",
    body: "Flag your own laptop, phone, or Tesla as missing — last-known GPS, accuracy radius, owner-consented recovery checklist. No covert tracking.",
  },
];

const DEVICE_BADGES = [
  { Icon: Server, label: "LINUX" },
  { Icon: Cpu, label: "WINDOWS" },
  { Icon: Activity, label: "MAC" },
  { Icon: Camera, label: "CAMERAS" },
  { Icon: Car, label: "TESLA" },
  { Icon: RadioTower, label: "IOT" },
];

export default function Landing() {
  const [stats, setStats] = useState(null);
  useEffect(() => {
    fetchStats().then(setStats).catch(() => {});
  }, []);

  return (
    <div className="min-h-screen bg-[#050505] text-white" data-testid="landing-root">
      {/* Top nav */}
      <header className="border-b border-[#222] sticky top-0 z-10 bg-[#050505]/90 backdrop-blur">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 border border-white flex items-center justify-center font-display font-bold">
              SG
            </div>
            <div>
              <div className="font-display font-bold tracking-tight">
                SENTINELGRID
                <span className="text-[#FF3B30] mx-1">/</span>
                <span className="text-[#888] font-mono text-xs">CORE</span>
              </div>
              <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
                UNIVERSAL ENDPOINT THREAT INTELLIGENCE
              </div>
            </div>
          </div>
          <Link
            to="/dashboard"
            data-testid="nav-launch-console"
            className="bg-white text-black hover:bg-[#00F5A0] transition-colors px-5 py-2.5 font-mono text-xs uppercase tracking-[0.2em] flex items-center gap-2"
          >
            LAUNCH CONSOLE <ArrowRight size={14} strokeWidth={1.5} />
          </Link>
        </div>
      </header>

      {/* Hero */}
      <section className="border-b border-[#222]">
        <div className="max-w-7xl mx-auto px-6 py-20 grid grid-cols-1 lg:grid-cols-12 gap-12 items-start">
          <div className="lg:col-span-7">
            <div className="text-[11px] font-mono uppercase tracking-[0.3em] text-[#666] mb-6 flex items-center gap-3">
              <span className="status-dot" style={{ background: "#00F5A0" }} />
              SYSTEM OPERATIONAL · LIVE TELEMETRY
            </div>
            <h1 className="font-display font-black tracking-[-0.02em] uppercase text-5xl md:text-6xl lg:text-7xl leading-[0.95]">
              FROM MEMORY
              <br />
              TO METAL —
              <br />
              <span className="text-[#FF3B30]">EVERY</span>{" "}
              <span className="text-[#00F5A0]">SURFACE</span>
              <br />
              ACCOUNTED FOR.
            </h1>
            <p className="text-[#aaa] mt-6 max-w-xl text-base leading-relaxed">
              A tactical SOC console that sees every byte on every device you own —
              servers, laptops, cameras, vehicles, IoT — with AI-driven scan verdicts,
              automatic incident correlation, and owner-consented asset recovery.
            </p>

            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Link
                to="/dashboard"
                data-testid="hero-cta-launch"
                className="bg-white text-black hover:bg-[#00F5A0] transition-colors px-6 py-3.5 font-mono text-xs uppercase tracking-[0.25em] flex items-center gap-2"
              >
                ENTER CONSOLE <Zap size={14} strokeWidth={1.5} />
              </Link>
              <a
                href="#pillars"
                data-testid="hero-cta-pillars"
                className="border border-[#444] hover:border-white hover:bg-[#111] px-6 py-3.5 font-mono text-xs uppercase tracking-[0.25em] transition-colors"
              >
                HOW IT WORKS
              </a>
            </div>

            <div className="mt-10 flex flex-wrap gap-2">
              {DEVICE_BADGES.map(({ Icon, label }) => (
                <div
                  key={label}
                  className="flex items-center gap-2 border border-[#222] px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.2em] text-[#888]"
                >
                  <Icon size={12} strokeWidth={1.5} />
                  {label}
                </div>
              ))}
              <div className="flex items-center gap-2 border border-[#222] px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.2em] text-[#888]">
                +4 MORE
              </div>
            </div>
          </div>

          {/* Live metric card */}
          <div className="lg:col-span-5 border border-[#222] bg-[#0a0a0a] p-6">
            <div className="flex items-center justify-between border-b border-[#222] pb-3 mb-4">
              <div className="text-[10px] font-mono uppercase tracking-[0.25em] text-[#666]">
                LIVE FLEET TELEMETRY
              </div>
              <ShieldAlert size={16} strokeWidth={1.5} className="text-[#FF3B30]" />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <Metric label="DEVICES" value={stats?.devices_total ?? "—"} />
              <Metric label="CLEAN" value={stats?.devices_clean ?? "—"} accent="#0044FF" />
              <Metric label="INFECTED" value={stats?.devices_infected ?? "—"} accent="#FF3B30" />
              <Metric label="MISSING" value={stats?.devices_missing ?? "—"} accent="#FFCC00" />
              <Metric label="SCANS" value={stats?.scans_performed ?? "—"} />
              <Metric label="INCIDENTS" value={stats?.open_incidents ?? "—"} accent="#00F5A0" />
              <Metric
                label="COVERAGE"
                value={stats ? `${stats.surface_coverage_pct}%` : "—"}
                accent="#fff"
              />
              <Metric
                label="VT ENGINE"
                value={stats?.vt_enabled ? "ONLINE" : "OFFLINE"}
                accent={stats?.vt_enabled ? "#00F5A0" : "#555"}
              />
            </div>
            <div className="mt-5 font-mono text-[10px] text-[#666] leading-relaxed">
              <span className="text-white">root@sentinel:~$</span> deep-scan --all
              --since 24h <span className="blink text-white">▮</span>
            </div>
          </div>
        </div>
      </section>

      {/* Pillars */}
      <section id="pillars" className="border-b border-[#222]">
        <div className="max-w-7xl mx-auto px-6 py-20">
          <div className="text-[11px] font-mono uppercase tracking-[0.3em] text-[#666] mb-3">
            // 04 CAPABILITIES
          </div>
          <h2 className="font-display font-bold tracking-tight text-3xl md:text-4xl uppercase max-w-2xl">
            Built for the analyst who actually opens the laptop at 3am.
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-[#222] mt-12 border border-[#222]">
            {PILLARS.map(({ Icon, title, body }) => (
              <div
                key={title}
                className="bg-[#0a0a0a] p-8 hover:bg-[#111] transition-colors"
                data-testid={`pillar-${title.toLowerCase().replace(" ", "-")}`}
              >
                <Icon size={22} strokeWidth={1.5} className="text-[#00F5A0] mb-5" />
                <h3 className="font-mono uppercase tracking-[0.2em] text-sm font-bold mb-3">
                  {title}
                </h3>
                <p className="text-[#aaa] text-sm leading-relaxed">{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="px-6 py-8 max-w-7xl mx-auto flex flex-col md:flex-row gap-3 items-center justify-between font-mono text-[10px] uppercase tracking-[0.25em] text-[#555]">
        <div>SENTINELGRID v0.2 · BUILT TACTICAL</div>
        <div className="flex items-center gap-3">
          <span className="status-dot" style={{ background: "#00F5A0" }} />
          UPLINK NOMINAL
        </div>
      </footer>
    </div>
  );
}

function Metric({ label, value, accent = "#fff" }) {
  return (
    <div className="border border-[#222] p-3 bg-[#070707]">
      <div className="text-[9px] font-mono uppercase tracking-[0.2em] text-[#666]">
        {label}
      </div>
      <div
        className="font-display font-bold text-2xl mt-1 leading-none"
        style={{ color: accent }}
      >
        {value}
      </div>
    </div>
  );
}
