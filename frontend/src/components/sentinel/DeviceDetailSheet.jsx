import { useEffect, useState } from "react";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import {
  fetchDeviceSurface,
  deviceAction,
} from "@/lib/api";
import { deviceIcon, STATUS_STYLES, DEVICE_META } from "@/lib/devices";
import { Loader2, ShieldOff, ShieldCheck, RefreshCw, Unlock } from "lucide-react";
import { toast } from "sonner";

const MEM_COLORS = {
  used:        "#0044FF",
  free:        "#1a1a1a",
  cache:       "#333333",
  kernel:      "#888888",
  suspicious:  "#FF3B30",
};

const CHECK_COLORS = {
  pass: "#00F5A0",
  warn: "#FFCC00",
  fail: "#FF3B30",
};

export default function DeviceDetailSheet({ deviceId, onClose, onChanged }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [acting, setActing] = useState(false);
  const open = Boolean(deviceId);

  useEffect(() => {
    if (!deviceId) {
      setData(null);
      return;
    }
    setLoading(true);
    fetchDeviceSurface(deviceId)
      .then(setData)
      .finally(() => setLoading(false));
  }, [deviceId]);

  async function act(action) {
    if (!deviceId) return;
    setActing(true);
    try {
      const r = await deviceAction(deviceId, action);
      toast.success(r.message);
      const fresh = await fetchDeviceSurface(deviceId);
      setData(fresh);
      onChanged?.();
    } catch (e) {
      toast.error("Action failed: " + (e?.message || "unknown"));
    } finally {
      setActing(false);
    }
  }

  const dev = data?.device;
  const Icon = dev ? deviceIcon(dev.device_type) : null;
  const status = dev ? STATUS_STYLES[dev.status] : null;

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent
        side="right"
        className="bg-[#070707] border-l border-[#222] rounded-none w-full sm:max-w-2xl p-0 overflow-y-auto text-white"
        data-testid="device-sheet"
      >
        <SheetHeader className="px-5 py-4 border-b border-[#222] bg-[#0a0a0a]">
          <SheetTitle className="text-white font-display tracking-tight flex items-center gap-3">
            {Icon ? <Icon size={20} strokeWidth={1.5} /> : null}
            <span>{dev?.hostname || "loading…"}</span>
            {status && (
              <span
                className="ml-auto inline-flex items-center gap-1.5 border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider"
                style={{ color: status.color, borderColor: status.color + "55" }}
              >
                <span className="status-dot" style={{ background: status.color }} />
                {status.label}
              </span>
            )}
          </SheetTitle>
        </SheetHeader>

        {loading || !data ? (
          <div className="p-10 text-center text-[#666] font-mono text-xs">
            <Loader2 className="animate-spin mx-auto mb-3" />
            loading surface map…
          </div>
        ) : (
          <div className="p-5 space-y-5">
            {/* Device meta */}
            <div className="grid grid-cols-2 gap-3 font-mono text-xs">
              <Meta label="DEVICE TYPE" value={DEVICE_META[dev.device_type]?.label || dev.device_type} />
              <Meta label="OS" value={dev.os} />
              <Meta label="IP" value={dev.ip_address} />
              <Meta label="LOCATION" value={dev.location} />
              <Meta label="FINGERPRINT" value={dev.fingerprint} />
              <Meta label="THREATS" value={dev.threats_detected} accent={dev.threats_detected ? "#FF3B30" : "#fff"} />
            </div>

            {/* Actions */}
            <div className="grid grid-cols-2 gap-2">
              <Button
                data-testid="action-quarantine"
                disabled={acting || dev.status === "quarantined"}
                onClick={() => act("quarantine")}
                className="bg-[#FF3B30] hover:bg-[#D62828] text-white rounded-none font-mono text-xs uppercase tracking-[0.2em] h-10"
              >
                <ShieldOff size={14} strokeWidth={1.5} className="mr-2" />
                QUARANTINE
              </Button>
              <Button
                data-testid="action-safe-remove"
                disabled={acting}
                onClick={() => act("safe_remove")}
                className="bg-white hover:bg-[#00F5A0] text-black rounded-none font-mono text-xs uppercase tracking-[0.2em] h-10"
              >
                <ShieldCheck size={14} strokeWidth={1.5} className="mr-2" />
                SAFE REMOVE
              </Button>
              <Button
                data-testid="action-rescan"
                disabled={acting}
                onClick={() => act("rescan")}
                variant="outline"
                className="border-[#444] bg-transparent hover:bg-[#1a1a1a] hover:border-white text-white rounded-none font-mono text-xs uppercase tracking-[0.2em] h-10"
              >
                <RefreshCw size={14} strokeWidth={1.5} className="mr-2" />
                DEEP RESCAN
              </Button>
              <Button
                data-testid="action-release"
                disabled={acting || dev.status !== "quarantined"}
                onClick={() => act("release")}
                variant="outline"
                className="border-[#444] bg-transparent hover:bg-[#1a1a1a] hover:border-white text-white rounded-none font-mono text-xs uppercase tracking-[0.2em] h-10"
              >
                <Unlock size={14} strokeWidth={1.5} className="mr-2" />
                RELEASE
              </Button>
            </div>

            {/* Memory Map */}
            <Section title="MEMORY MAP" subtitle="64-block surface • 1 block ≈ random page">
              <div className="grid grid-cols-16 gap-0.5 p-2 border border-[#222] bg-[#040404]"
                   style={{ gridTemplateColumns: "repeat(16, minmax(0,1fr))" }}>
                {data.memory_blocks.map((b) => (
                  <div
                    key={b.id}
                    title={`${b.kind} • ${b.size_kb}KB`}
                    className="mem-block aspect-square"
                    style={{ background: MEM_COLORS[b.kind] }}
                  />
                ))}
              </div>
              <div className="flex flex-wrap gap-3 mt-2 font-mono text-[10px] text-[#666]">
                {Object.entries(MEM_COLORS).map(([k, c]) => (
                  <span key={k} className="flex items-center gap-1.5 uppercase">
                    <span className="w-2.5 h-2.5" style={{ background: c }} />
                    {k}
                  </span>
                ))}
              </div>
            </Section>

            {/* RAT checks */}
            <Section title="RAT / ROOTKIT SURFACE CHECKS">
              <ul className="border border-[#222] divide-y divide-[#1a1a1a]">
                {data.rat_checks.map((c, i) => (
                  <li key={i} className="flex items-center justify-between px-3 py-2 font-mono text-xs">
                    <span className="text-[#ddd]">{c.check}</span>
                    <span
                      className="font-bold uppercase tracking-wider"
                      style={{ color: CHECK_COLORS[c.status] }}
                    >
                      {c.status}
                    </span>
                  </li>
                ))}
              </ul>
            </Section>

            {/* Processes */}
            <Section title="RUNNING PROCESSES" subtitle={`${data.processes.length} observed`}>
              <div className="border border-[#222] overflow-x-auto">
                <table className="w-full font-mono text-[11px]">
                  <thead className="text-[10px] uppercase text-[#666] bg-[#0a0a0a]">
                    <tr>
                      <th className="px-2 py-1.5 text-left">PID</th>
                      <th className="px-2 py-1.5 text-left">NAME</th>
                      <th className="px-2 py-1.5 text-left">PATH</th>
                      <th className="px-2 py-1.5 text-right">CPU</th>
                      <th className="px-2 py-1.5 text-right">MEM</th>
                      <th className="px-2 py-1.5 text-left">STATE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.processes.map((p) => {
                      const sus = p.state === "suspicious";
                      return (
                        <tr
                          key={p.pid}
                          className={`border-t border-[#1a1a1a] ${sus ? "bg-[#1d0908]" : ""}`}
                        >
                          <td className="px-2 py-1.5 text-[#888]">{p.pid}</td>
                          <td className="px-2 py-1.5 text-white">{p.name}</td>
                          <td className="px-2 py-1.5 text-[#888] truncate max-w-[220px]" title={p.path}>{p.path}</td>
                          <td className="px-2 py-1.5 text-right text-[#ddd]">{p.cpu}%</td>
                          <td className="px-2 py-1.5 text-right text-[#ddd]">{p.mem}%</td>
                          <td
                            className="px-2 py-1.5 uppercase"
                            style={{ color: sus ? "#FF3B30" : "#888" }}
                          >
                            {p.state}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </Section>

            {/* Network */}
            <Section title="NETWORK CONNECTIONS">
              <div className="border border-[#222]">
                {data.network.map((n, i) => {
                  const bad = n.remote.includes(":4444");
                  return (
                    <div
                      key={i}
                      className="flex items-center justify-between px-3 py-1.5 font-mono text-[11px] border-t border-[#1a1a1a] first:border-t-0"
                      style={bad ? { background: "#1d0908" } : {}}
                    >
                      <span className="text-[#888] uppercase">{n.proto}</span>
                      <span className={bad ? "text-[#FF3B30]" : "text-white"}>{n.remote}</span>
                      <span className="text-[#888]">{n.state}</span>
                    </div>
                  );
                })}
              </div>
            </Section>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}

function Meta({ label, value, accent }) {
  return (
    <div className="border border-[#222] bg-[#0a0a0a] p-2">
      <div className="text-[9px] uppercase tracking-[0.2em] text-[#666]">{label}</div>
      <div className="text-xs mt-0.5 truncate" style={{ color: accent || "#fff" }}>
        {value}
      </div>
    </div>
  );
}

function Section({ title, subtitle, children }) {
  return (
    <div>
      <div className="flex items-baseline justify-between mb-2">
        <h3 className="font-mono uppercase tracking-[0.2em] text-xs text-white">
          {title}
        </h3>
        {subtitle && (
          <span className="font-mono text-[10px] text-[#666]">{subtitle}</span>
        )}
      </div>
      {children}
    </div>
  );
}
