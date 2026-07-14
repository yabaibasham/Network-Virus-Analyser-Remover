import { useState } from "react";
import { Building2, ChevronDown, Plus, Users, Check } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { switchOrg } from "@/lib/api";
import { toast } from "sonner";

const ROLE_COLOR = { owner: "#00F5A0", analyst: "#FFCC00", viewer: "#888" };

export default function OrgSwitcher({ orgs = [], activeOrgId, role, superadmin, onManage, onNew }) {
  const [switching, setSwitching] = useState(false);
  const active = orgs.find((o) => o.org_id === activeOrgId);

  async function pick(orgId) {
    if (orgId === activeOrgId) return;
    setSwitching(true);
    try {
      await switchOrg(orgId);
      window.location.reload();
    } catch {
      toast.error("Could not switch organisation");
      setSwitching(false);
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          data-testid="org-switcher"
          disabled={switching}
          className="flex items-center gap-2 border border-[#333] hover:border-white px-3 py-1.5 transition-colors max-w-[220px]"
        >
          <Building2 size={14} strokeWidth={1.5} className="shrink-0 text-[#888]" />
          <span className="font-mono text-[11px] text-white truncate">
            {active ? active.name : "Select org"}
          </span>
          <span
            className="font-mono text-[8px] uppercase px-1 py-0.5 border shrink-0"
            style={{ color: ROLE_COLOR[role] || "#888", borderColor: (ROLE_COLOR[role] || "#888") + "66" }}
          >
            {role || "—"}
          </span>
          <ChevronDown size={13} className="shrink-0 text-[#666]" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="end"
        className="bg-[#0a0a0a] border border-[#222] rounded-none text-white w-64"
        data-testid="org-switcher-menu"
      >
        <DropdownMenuLabel className="font-mono text-[9px] uppercase tracking-[0.2em] text-[#666]">
          {superadmin ? "All organisations (super-admin)" : "Your organisations"}
        </DropdownMenuLabel>
        <DropdownMenuSeparator className="bg-[#222]" />
        <div className="max-h-64 overflow-y-auto">
          {orgs.map((o) => (
            <DropdownMenuItem
              key={o.org_id}
              data-testid={`org-option-${o.org_id}`}
              onClick={() => pick(o.org_id)}
              className="font-mono text-xs cursor-pointer focus:bg-[#161616] flex items-center justify-between"
            >
              <span className="truncate">{o.name}</span>
              <span className="flex items-center gap-1.5">
                <span className="text-[9px] uppercase" style={{ color: ROLE_COLOR[o.role] || "#888" }}>
                  {o.role}
                </span>
                {o.org_id === activeOrgId && <Check size={12} className="text-[#00F5A0]" />}
              </span>
            </DropdownMenuItem>
          ))}
        </div>
        <DropdownMenuSeparator className="bg-[#222]" />
        {(role === "owner" || superadmin) && (
          <DropdownMenuItem
            data-testid="manage-members"
            onClick={onManage}
            className="font-mono text-xs cursor-pointer focus:bg-[#161616]"
          >
            <Users size={13} className="mr-2" /> Manage members
          </DropdownMenuItem>
        )}
        <DropdownMenuItem
          data-testid="new-org"
          onClick={onNew}
          className="font-mono text-xs cursor-pointer focus:bg-[#161616]"
        >
          <Plus size={13} className="mr-2" /> New organisation
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
