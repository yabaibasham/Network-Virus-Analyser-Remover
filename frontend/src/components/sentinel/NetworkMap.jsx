import { useEffect, useMemo, useState } from "react";
import { Network, RefreshCw, Loader2, Radio } from "lucide-react";
import { fetchTopology } from "@/lib/api";

const NODE_COLOR = {
  clean: "#0044FF",
  infected: "#FF3B30",
  quarantined: "#888888",
  scanning: "#FFCC00",
  offline: "#444444",
  hostile: "#FF3B30",
};

const W = 1000;
const H = 620;

function edgePath(a, b) {
  const mx = (a.x + b.x) / 2;
  return `M ${a.x} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x} ${b.y}`;
}

export default function NetworkMap({ onSelect }) {
  const [topo, setTopo] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    try {
      const d = await fetchTopology();
      setTopo(d);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const layout = useMemo(() => {
    if (!topo) return null;
    const buckets = { wan: [], gateway: [], subnet: [], endpoint: [], threat: [] };
    topo.nodes.forEach((n) => buckets[n.kind]?.push(n));
    const pos = {};
    const place = (arr, x) => {
      const n = arr.length;
      arr.forEach((node, i) => {
        const y = n <= 1 ? H / 2 : H * 0.08 + (i * (H * 0.84)) / (n - 1);
        pos[node.id] = { x, y, node };
      });
    };
    place(buckets.wan, 70);
    place(buckets.gateway, 250);
    place(buckets.subnet, 470);
    place(buckets.endpoint, 730);
    buckets.threat.forEach((t) => {
      const link = topo.links.find((l) => l.target === t.id);
      const srcY = link && pos[link.source] ? pos[link.source].y : H / 2;
      pos[t.id] = { x: 940, y: srcY - 26, node: t };
    });
    return pos;
  }, [topo]);

  const s = topo?.summary;

  return (
    <div className="bg-[#0d0d0d] border border-[#222] fade-up" data-testid="network-map">
      <div className="flex items-center justify-between border-b border-[#222] px-4 py-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
            // LAN · WAN TOPOLOGY
          </div>
          <h2 className="font-display font-bold text-lg tracking-tight flex items-center gap-2">
            <Network size={16} strokeWidth={1.5} /> NETWORK MAP
          </h2>
        </div>
        <div className="flex items-center gap-4 font-mono text-[11px] text-[#888]">
          {s && (
            <>
              <span>GATEWAY <span className="text-white">{s.gateway}</span></span>
              <span>ENDPOINTS <span className="text-white">{s.endpoints}</span></span>
              <span>SUBNETS <span className="text-white">{s.subnets}</span></span>
              <span className={s.hostile_links ? "text-[#FF3B30]" : ""}>
                HOSTILE <span className="text-white">{s.hostile_links}</span>
              </span>
            </>
          )}
          <button
            data-testid="network-refresh"
            onClick={load}
            className="border border-[#444] hover:border-white p-1.5 transition-colors"
            title="rescan"
          >
            <RefreshCw size={13} strokeWidth={1.5} className={loading ? "animate-spin" : ""} />
          </button>
        </div>
      </div>

      <div className="relative overflow-hidden">
        <div className="radar-sweep" style={{ mixBlendMode: "screen" }} />
        {loading && !topo ? (
          <div className="p-16 text-center text-[#666] font-mono text-xs">
            <Loader2 className="animate-spin mx-auto mb-3" /> mapping network fabric…
          </div>
        ) : (
          <svg
            viewBox={`0 0 ${W} ${H}`}
            className="w-full h-auto relative z-[2]"
            preserveAspectRatio="xMidYMid meet"
          >
            {/* column guides */}
            {["OWNER FLEET", "GATEWAY", "SUBNETS", "ENDPOINTS", "WAN THREATS"].map(
              (lbl, i) => (
                <text
                  key={lbl}
                  x={[70, 250, 470, 730, 900][i]}
                  y={26}
                  fill="#555"
                  fontSize="11"
                  fontFamily="JetBrains Mono, monospace"
                  textAnchor="middle"
                  letterSpacing="1.5"
                >
                  {lbl}
                </text>
              )
            )}

            {/* links */}
            {topo.links.map((l, i) => {
              const a = layout[l.source];
              const b = layout[l.target];
              if (!a || !b) return null;
              const hostile = l.status === "hostile";
              const infected = l.status === "infected";
              const color = hostile || infected ? "#FF3B30" : "#2a2a2a";
              return (
                <path
                  key={i}
                  d={edgePath(a, b)}
                  fill="none"
                  stroke={color}
                  strokeWidth={hostile ? 1.6 : 1}
                  className={hostile ? "link-hostile" : "link-flow"}
                  opacity={hostile ? 0.9 : 0.6}
                />
              );
            })}

            {/* nodes */}
            {Object.values(layout).map(({ x, y, node }) => {
              const color = NODE_COLOR[node.status] || "#888";
              if (node.kind === "wan")
                return (
                  <g key={node.id}>
                    <circle cx={x} cy={y} r={16} fill="none" stroke="#00F5A0" strokeWidth="1.2" />
                    <circle cx={x} cy={y} r={5} fill="#00F5A0" />
                    <text x={x} y={y + 34} fill="#aaa" fontSize="11" textAnchor="middle" fontFamily="JetBrains Mono, monospace">
                      INTERNET
                    </text>
                  </g>
                );
              if (node.kind === "gateway")
                return (
                  <g key={node.id}>
                    <rect x={x - 13} y={y - 13} width={26} height={26} fill="#0a0a0a" stroke="#fff" strokeWidth="1.4" />
                    <text x={x} y={y + 34} fill="#fff" fontSize="11" textAnchor="middle" fontFamily="JetBrains Mono, monospace">
                      {node.label}
                    </text>
                    <text x={x} y={y + 48} fill="#666" fontSize="10" textAnchor="middle" fontFamily="JetBrains Mono, monospace">
                      {node.ip}
                    </text>
                  </g>
                );
              if (node.kind === "subnet")
                return (
                  <g key={node.id}>
                    <rect x={x - 42} y={y - 12} width={84} height={24} fill="#0a0a0a" stroke={color} strokeWidth="1.2" opacity="0.9" />
                    <text x={x} y={y + 4} fill={color} fontSize="10.5" textAnchor="middle" fontFamily="JetBrains Mono, monospace">
                      {node.label}
                    </text>
                    <text x={x} y={y + 26} fill="#666" fontSize="9" textAnchor="middle" fontFamily="JetBrains Mono, monospace">
                      {node.count} hosts
                    </text>
                  </g>
                );
              if (node.kind === "threat")
                return (
                  <g key={node.id} className="pulse-soft">
                    <circle cx={x} cy={y} r={7} fill="#FF3B30" />
                    <text x={x} y={y - 12} fill="#FF3B30" fontSize="9.5" textAnchor="middle" fontFamily="JetBrains Mono, monospace">
                      C2 · {node.label}
                    </text>
                  </g>
                );
              // endpoint
              const infected = node.status === "infected";
              return (
                <g
                  key={node.id}
                  onClick={() => onSelect?.(node.id)}
                  style={{ cursor: "pointer" }}
                  data-testid={`net-endpoint-${node.id}`}
                  className="net-endpoint"
                >
                  {infected && (
                    <circle cx={x} cy={y} r={13} fill="none" stroke="#FF3B30" strokeWidth="1" className="pulse-soft" />
                  )}
                  <circle cx={x} cy={y} r={7} fill={color} stroke="#050505" strokeWidth="1.5" />
                  <text x={x + 14} y={y - 2} fill="#ddd" fontSize="11" fontFamily="JetBrains Mono, monospace">
                    {node.label}
                  </text>
                  <text x={x + 14} y={y + 11} fill="#666" fontSize="9.5" fontFamily="JetBrains Mono, monospace">
                    {node.ip} · {node.status.toUpperCase()}
                  </text>
                </g>
              );
            })}
          </svg>
        )}
      </div>

      <div className="border-t border-[#222] px-4 py-2 flex flex-wrap items-center gap-4 font-mono text-[10px] text-[#666]">
        <span className="flex items-center gap-1.5"><Radio size={11} className="text-[#00F5A0]" /> click a node to inspect its surface</span>
        {Object.entries({ clean: "CLEAN", infected: "INFECTED", quarantined: "QUARANTINED", hostile: "C2 / HOSTILE" }).map(
          ([k, lbl]) => (
            <span key={k} className="flex items-center gap-1.5 uppercase">
              <span className="w-2.5 h-2.5 rounded-full" style={{ background: NODE_COLOR[k] }} />
              {lbl}
            </span>
          )
        )}
      </div>
    </div>
  );
}
