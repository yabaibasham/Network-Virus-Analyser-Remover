import {
  ShieldAlert,
  Activity,
  Cpu,
  Crosshair,
  RadioTower,
  TerminalSquare,
  Settings,
} from "lucide-react";

const NAV = [
  { Icon: ShieldAlert, label: "OVERVIEW", id: "overview", active: true },
  { Icon: Activity, label: "FLEET", id: "fleet" },
  { Icon: Crosshair, label: "SCANNER", id: "scanner" },
  { Icon: RadioTower, label: "FEED", id: "feed" },
  { Icon: TerminalSquare, label: "CONSOLE", id: "console" },
  { Icon: Cpu, label: "AGENTS", id: "agents" },
];

export default function Sidebar() {
  return (
    <aside
      className="w-16 hidden md:flex flex-col border-r border-[#222] bg-[#070707] items-center py-5 gap-6 sticky top-0 h-screen z-20"
      data-testid="sidebar"
    >
      <div className="w-9 h-9 border border-white flex items-center justify-center font-display font-bold text-base">
        SG
      </div>
      <nav className="flex flex-col gap-1 mt-2">
        {NAV.map(({ Icon, label, id, active }) => (
          <button
            key={id}
            data-testid={`nav-${id}`}
            title={label}
            className={`group relative w-10 h-10 flex items-center justify-center border ${
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
          </button>
        ))}
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
