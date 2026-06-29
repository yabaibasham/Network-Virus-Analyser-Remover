import { useEffect, useState } from "react";
import { ShieldAlert, Globe2 } from "lucide-react";

function useClock() {
  const [t, setT] = useState(new Date());
  useEffect(() => {
    const id = setInterval(() => setT(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return t;
}

export default function HeaderBar({ logs = [], stats }) {
  const clock = useClock();
  const top = logs.slice(0, 12);
  const utc = clock.toISOString().replace("T", " ").slice(0, 19);

  return (
    <header className="border-b border-[#222] bg-[#070707] z-10" data-testid="header-bar">
      <div className="flex items-center justify-between px-4 py-3 gap-4">
        <div className="flex items-center gap-3 min-w-0">
          <ShieldAlert size={22} strokeWidth={1.5} className="text-white" />
          <div className="leading-tight">
            <div className="font-display font-bold text-base tracking-tight">
              SENTINELGRID
              <span className="text-[#FF3B30] ml-1">/</span>
              <span className="text-[#888] font-mono text-xs ml-1">CORE</span>
            </div>
            <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
              UNIVERSAL ENDPOINT THREAT INTELLIGENCE
            </div>
          </div>
        </div>
        <div className="hidden md:flex items-center gap-5 font-mono text-[11px] text-[#888]">
          <div className="flex items-center gap-2">
            <Globe2 size={14} strokeWidth={1.5} />
            <span className="text-white">{utc}</span>
            <span className="text-[#555]">UTC</span>
          </div>
          {stats && (
            <>
              <span className="text-[#555]">|</span>
              <span>
                COVERAGE{" "}
                <span className="text-white">{stats.surface_coverage_pct}%</span>
              </span>
              <span className="text-[#555]">|</span>
              <span>
                FLEET <span className="text-white">{stats.devices_total}</span>
              </span>
              <span>
                <span className="text-[#FF3B30]">●</span>{" "}
                {stats.devices_infected} INF
              </span>
            </>
          )}
        </div>
      </div>
      {/* Marquee */}
      <div
        className="border-t border-[#222] bg-[#0a0a0a] overflow-hidden h-7 flex items-center"
        data-testid="threat-marquee"
      >
        <div className="flex marquee-track whitespace-nowrap will-change-transform">
          {[...top, ...top].map((l, idx) => (
            <span
              key={`${l.id}-${idx}`}
              className="font-mono text-[11px] px-6 flex items-center gap-2"
            >
              <span
                className="status-dot"
                style={{
                  background:
                    l.severity === "critical" || l.severity === "danger"
                      ? "#FF3B30"
                      : l.severity === "warning"
                      ? "#FFCC00"
                      : "#0044FF",
                }}
              />
              <span className="text-[#666]">
                {(l.timestamp || "").slice(11, 19)}
              </span>
              <span className="text-[#888]">[{l.category}]</span>
              <span className="text-white">{l.message}</span>
            </span>
          ))}
        </div>
      </div>
    </header>
  );
}
