import { useState } from "react";
import { DEVICE_META, STATUS_STYLES, deviceIcon } from "@/lib/devices";
import { Search } from "lucide-react";
import { Input } from "@/components/ui/input";

function StatusBadge({ status }) {
  const s = STATUS_STYLES[status] || STATUS_STYLES.offline;
  const isInfected = status === "infected";
  return (
    <span
      className={`inline-flex items-center gap-1.5 border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
        isInfected ? "danger-pulse" : ""
      }`}
      style={{ color: s.color, borderColor: s.color + "55" }}
    >
      <span className="status-dot" style={{ background: s.color }} />
      {s.label}
    </span>
  );
}

function LoadBar({ value, color = "#FFFFFF" }) {
  const pct = Math.max(0, Math.min(100, value));
  return (
    <div className="w-full h-1.5 bg-[#1a1a1a] relative overflow-hidden">
      <div
        className="absolute inset-y-0 left-0"
        style={{ width: `${pct}%`, background: color }}
      />
    </div>
  );
}

export default function FleetGrid({ devices, loading, onSelect }) {
  const [q, setQ] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");

  const filtered = devices.filter((d) => {
    const m =
      !q ||
      d.hostname.toLowerCase().includes(q.toLowerCase()) ||
      d.ip_address.includes(q) ||
      d.os.toLowerCase().includes(q.toLowerCase()) ||
      d.location.toLowerCase().includes(q.toLowerCase());
    const s = statusFilter === "all" || d.status === statusFilter;
    return m && s;
  });

  const FILTERS = ["all", "clean", "infected", "quarantined", "scanning"];

  return (
    <div
      className="bg-[#0d0d0d] border border-[#222]"
      data-testid="fleet-grid"
    >
      <div className="flex items-center justify-between border-b border-[#222] px-4 py-3 gap-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
            // SECTION 01
          </div>
          <h2 className="font-display font-bold text-lg tracking-tight">
            FLEET SURFACE GRID
            <span className="ml-2 font-mono text-xs text-[#666]">
              [{filtered.length}/{devices.length}]
            </span>
          </h2>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search
              size={14}
              className="absolute left-2 top-1/2 -translate-y-1/2 text-[#666]"
              strokeWidth={1.5}
            />
            <Input
              data-testid="fleet-search"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="search host / ip / os / loc"
              className="bg-[#0a0a0a] border-[#333] rounded-none text-xs font-mono pl-7 h-8 w-56 focus-visible:ring-0 focus-visible:border-white"
            />
          </div>
        </div>
      </div>
      <div className="flex border-b border-[#222] bg-[#0a0a0a]">
        {FILTERS.map((f) => (
          <button
            key={f}
            data-testid={`filter-${f}`}
            onClick={() => setStatusFilter(f)}
            className={`px-3 py-2 font-mono text-[10px] uppercase tracking-[0.15em] border-r border-[#222] transition-colors ${
              statusFilter === f
                ? "bg-white text-black"
                : "text-[#888] hover:text-white hover:bg-[#161616]"
            }`}
          >
            {f}
          </button>
        ))}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead className="text-[10px] font-mono uppercase text-[#666] tracking-[0.15em] bg-[#0a0a0a]">
            <tr>
              <th className="px-4 py-2 font-normal">HOST</th>
              <th className="px-3 py-2 font-normal">TYPE</th>
              <th className="px-3 py-2 font-normal">OS</th>
              <th className="px-3 py-2 font-normal">IP</th>
              <th className="px-3 py-2 font-normal">LOC</th>
              <th className="px-3 py-2 font-normal w-28">MEM</th>
              <th className="px-3 py-2 font-normal w-28">CPU</th>
              <th className="px-3 py-2 font-normal">STATUS</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={8} className="px-4 py-6 text-center text-[#666] font-mono text-xs">
                  initialising surface scan…
                </td>
              </tr>
            )}
            {!loading &&
              filtered.map((d, idx) => {
                const Icon = deviceIcon(d.device_type);
                return (
                  <tr
                    key={d.id}
                    data-testid={`device-row-${idx}`}
                    onClick={() => onSelect(d.id)}
                    className="border-b border-[#161616] hover:bg-[#141414] cursor-pointer group transition-colors"
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Icon
                          size={16}
                          strokeWidth={1.5}
                          className="text-[#888] group-hover:text-white"
                        />
                        <span className="font-mono text-xs">{d.hostname}</span>
                      </div>
                    </td>
                    <td className="px-3 py-3 font-mono text-[10px] uppercase text-[#888]">
                      {DEVICE_META[d.device_type]?.label || d.device_type}
                    </td>
                    <td className="px-3 py-3 font-mono text-[11px] text-[#aaa]">{d.os}</td>
                    <td className="px-3 py-3 font-mono text-[11px] text-[#aaa]">{d.ip_address}</td>
                    <td className="px-3 py-3 font-mono text-[11px] text-[#888]">{d.location}</td>
                    <td className="px-3 py-3">
                      <LoadBar
                        value={d.memory_load}
                        color={d.memory_load > 80 ? "#FF3B30" : d.memory_load > 60 ? "#FFCC00" : "#0044FF"}
                      />
                      <div className="font-mono text-[10px] text-[#666] mt-1">
                        {d.memory_load.toFixed(1)}%
                      </div>
                    </td>
                    <td className="px-3 py-3">
                      <LoadBar
                        value={d.cpu_load}
                        color={d.cpu_load > 80 ? "#FF3B30" : d.cpu_load > 60 ? "#FFCC00" : "#00F5A0"}
                      />
                      <div className="font-mono text-[10px] text-[#666] mt-1">
                        {d.cpu_load.toFixed(1)}%
                      </div>
                    </td>
                    <td className="px-3 py-3">
                      <StatusBadge status={d.status} />
                    </td>
                  </tr>
                );
              })}
            {!loading && filtered.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-[#666] font-mono text-xs">
                  no devices match filter
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
