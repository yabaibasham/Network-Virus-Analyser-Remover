import { LayoutDashboard, Network, Users, Wrench, Settings } from "lucide-react";

const NAV = [
  { Icon: LayoutDashboard, label: "OPS", id: "overview" },
  { Icon: Network, label: "NET", id: "network" },
  { Icon: Users, label: "WATCH", id: "community" },
  { Icon: Wrench, label: "FIX", id: "remediation" },
];

export default function Sidebar({ view = "overview", setView }) {
  return (
    <aside
      className="w-16 hidden md:flex flex-col border-r border-[#222] bg-[#070707] items-center py-5 gap-4 sticky top-0 h-screen z-20"
      data-testid="sidebar"
    >
      <div className="w-9 h-9 border border-white flex items-center justify-center font-display font-bold text-base">
        SG
      </div>
      <nav className="flex flex-col gap-1.5 mt-2">
        {NAV.map(({ Icon, label, id }) => {
          const active = view === id;
          return (
            <button
              key={id}
              data-testid={`nav-${id}`}
              title={label}
              onClick={() => setView?.(id)}
              className={`group relative w-11 flex flex-col items-center gap-1 py-2 border ${
                active
                  ? "border-white bg-[#111]"
                  : "border-transparent hover:border-[#444]"
              } transition-colors`}
            >
              <Icon
                size={18}
                strokeWidth={1.5}
                className={active ? "text-white" : "text-[#666] group-hover:text-white"}
              />
              <span
                className={`font-mono text-[7px] tracking-[0.15em] ${
                  active ? "text-white" : "text-[#555] group-hover:text-[#999]"
                }`}
              >
                {label}
              </span>
            </button>
          );
        })}
      </nav>
      <div className="mt-auto">
        <button
          data-testid="nav-settings"
          className="w-10 h-10 flex items-center justify-center hover:border hover:border-[#444]"
        >
          <Settings size={18} strokeWidth={1.5} className="text-[#666]" />
        </button>
      </div>
    </aside>
  );
}
