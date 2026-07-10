import { useState } from "react";
import { FolderKanban, ChevronDown, ChevronRight } from "lucide-react";
import { updateIncidentStatus } from "@/lib/api";
import { toast } from "sonner";

const SEV_COLOR = {
  info: "#0044FF",
  warning: "#FFCC00",
  danger: "#FF3B30",
  critical: "#FF3B30",
};

const STATUS_FLOW = ["open", "triaged", "contained", "closed"];

export default function IncidentsPanel({ incidents = [], onChanged }) {
  const [expanded, setExpanded] = useState(null);

  async function advance(inc) {
    const next = STATUS_FLOW[Math.min(STATUS_FLOW.indexOf(inc.status) + 1, STATUS_FLOW.length - 1)];
    if (next === inc.status) return;
    try {
      await updateIncidentStatus(inc.id, next);
      toast.success(`${inc.title} → ${next.toUpperCase()}`);
      onChanged?.();
    } catch {
      toast.error("Update failed");
    }
  }

  const open = incidents.filter((i) => i.status !== "closed");
  const closed = incidents.filter((i) => i.status === "closed");

  return (
    <div className="bg-[#0d0d0d] border border-[#222]" data-testid="incidents-panel">
      <div className="flex items-center justify-between border-b border-[#222] px-4 py-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
            // SECTION 05
          </div>
          <h2 className="font-display font-bold text-lg tracking-tight flex items-center gap-2">
            <FolderKanban size={16} strokeWidth={1.5} />
            INCIDENT QUEUE
            <span className="font-mono text-xs text-[#666] ml-1">
              [{open.length} OPEN · {closed.length} CLOSED]
            </span>
          </h2>
        </div>
      </div>

      <div className="divide-y divide-[#1a1a1a]">
        {incidents.length === 0 && (
          <div className="font-mono text-xs text-[#666] p-4">
            no incidents yet · run a scan or wait for telemetry
          </div>
        )}
        {incidents.map((inc) => {
          const isOpen = expanded === inc.id;
          const sevColor = SEV_COLOR[inc.severity] || "#888";
          return (
            <div key={inc.id} data-testid={`incident-${inc.id}`}>
              <button
                onClick={() => setExpanded(isOpen ? null : inc.id)}
                className="w-full text-left px-4 py-2.5 hover:bg-[#141414] transition-colors flex items-center gap-3"
                data-testid={`incident-toggle-${inc.id}`}
              >
                {isOpen ? (
                  <ChevronDown size={14} strokeWidth={1.5} className="text-[#666] shrink-0" />
                ) : (
                  <ChevronRight size={14} strokeWidth={1.5} className="text-[#666] shrink-0" />
                )}
                <span className="status-dot shrink-0" style={{ background: sevColor }} />
                <span className="font-mono text-xs text-white truncate flex-1">
                  {inc.title}
                </span>
                <span className="font-mono text-[10px] uppercase text-[#888] hidden sm:inline">
                  {inc.category}
                </span>
                <span
                  className="font-mono text-[10px] uppercase border px-2 py-0.5 shrink-0"
                  style={{
                    color: inc.status === "closed" ? "#888" : "#fff",
                    borderColor: inc.status === "closed" ? "#333" : "#fff",
                  }}
                >
                  {inc.status}
                </span>
              </button>

              {isOpen && (
                <div className="px-4 pb-4 pt-1 bg-[#070707]">
                  <div className="font-mono text-[11px] text-[#aaa] mb-3">
                    {inc.summary}
                  </div>
                  <div className="border border-[#222] bg-[#040404] p-3 font-mono text-[11px] max-h-48 overflow-y-auto">
                    <div className="text-[#666] uppercase text-[9px] tracking-[0.2em] mb-2">
                      TIMELINE · {inc.timeline?.length || 0} events
                    </div>
                    {(inc.timeline || []).map((t, i) => (
                      <div key={i} className="flex gap-2 py-0.5">
                        <span className="text-[#555] shrink-0">
                          {(t.at || "").slice(11, 19)}
                        </span>
                        <span
                          className="shrink-0 font-bold w-12"
                          style={{ color: SEV_COLOR[t.severity] || "#888" }}
                        >
                          {(t.severity || "info").toUpperCase().slice(0, 4)}
                        </span>
                        <span className="text-[#ddd]">{t.event}</span>
                      </div>
                    ))}
                  </div>
                  <div className="mt-3 flex items-center gap-2 flex-wrap">
                    {STATUS_FLOW.map((s) => (
                      <div
                        key={s}
                        className="font-mono text-[10px] uppercase px-2 py-1 border"
                        style={{
                          color: s === inc.status ? "#000" : "#888",
                          background: s === inc.status ? "#fff" : "transparent",
                          borderColor: s === inc.status ? "#fff" : "#333",
                        }}
                      >
                        {s}
                      </div>
                    ))}
                    {inc.status !== "closed" && (
                      <button
                        data-testid={`incident-advance-${inc.id}`}
                        onClick={() => advance(inc)}
                        className="ml-auto font-mono text-[10px] uppercase tracking-[0.2em] border border-[#444] hover:bg-[#1a1a1a] hover:border-white px-3 py-1 transition-colors"
                      >
                        advance →
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
