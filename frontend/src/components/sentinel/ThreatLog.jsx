import { ScrollArea } from "@/components/ui/scroll-area";

const SEV = {
  info:     { color: "#0044FF", tag: "INFO" },
  warning:  { color: "#FFCC00", tag: "WARN" },
  danger:   { color: "#FF3B30", tag: "DNGR" },
  critical: { color: "#FF3B30", tag: "CRIT" },
};

export default function ThreatLog({ logs = [] }) {
  return (
    <div className="bg-[#0d0d0d] border border-[#222]" data-testid="threat-log">
      <div className="flex items-center justify-between border-b border-[#222] px-4 py-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
            // SECTION 03
          </div>
          <h2 className="font-display font-bold text-lg tracking-tight">
            THREAT LOG
            <span className="ml-2 font-mono text-xs text-[#666]">[{logs.length}]</span>
          </h2>
        </div>
        <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[#666]">
          <span className="status-dot" style={{ background: "#00F5A0" }} />
          LIVE
        </div>
      </div>
      <ScrollArea className="h-72">
        <div className="scanlines p-4 font-mono text-[11px] leading-relaxed">
          {logs.map((l) => {
            const s = SEV[l.severity] || SEV.info;
            return (
              <div
                key={l.id}
                className="flex gap-3 hover:bg-[#141414] px-2 -mx-2 py-0.5"
                data-testid={`log-row-${l.id}`}
              >
                <span className="text-[#555] shrink-0">
                  {(l.timestamp || "").slice(11, 19)}
                </span>
                <span
                  className="font-bold shrink-0 w-12"
                  style={{ color: s.color }}
                >
                  {s.tag}
                </span>
                <span className="text-[#888] shrink-0 w-24">[{l.category}]</span>
                {l.device_hostname && (
                  <span className="text-[#0044FF] shrink-0">
                    {l.device_hostname}
                  </span>
                )}
                <span className="text-[#ddd]">{l.message}</span>
              </div>
            );
          })}
          {logs.length === 0 && (
            <div className="text-[#666] text-center py-8">no events recorded</div>
          )}
          <div className="text-white mt-2">
            <span className="text-[#666]">root@sentinel:~$ </span>
            <span className="blink">▮</span>
          </div>
        </div>
      </ScrollArea>
    </div>
  );
}
