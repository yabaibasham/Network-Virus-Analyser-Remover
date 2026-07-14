import { useEffect, useState, useCallback } from "react";
import { Users, UserPlus, Trash2, Loader2, MailX } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  fetchCurrentOrg,
  inviteMember,
  revokeInvite,
  changeMemberRole,
  removeMember,
} from "@/lib/api";
import { toast } from "sonner";

const ROLES = ["owner", "analyst", "viewer"];
const ROLE_COLOR = { owner: "#00F5A0", analyst: "#FFCC00", viewer: "#888" };

export default function MembersDialog({ open, onOpenChange, currentUserId }) {
  const [data, setData] = useState(null);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("analyst");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    fetchCurrentOrg().then(setData).catch(() => toast.error("Could not load members"));
  }, []);

  useEffect(() => {
    if (open) load();
  }, [open, load]);

  async function invite() {
    if (!email.trim() || !email.includes("@")) {
      toast.error("Enter a valid email");
      return;
    }
    setBusy(true);
    try {
      await inviteMember(email.trim().toLowerCase(), role);
      toast.success(`Invited ${email.trim()}`);
      setEmail("");
      load();
    } catch {
      /* 403 handled globally */
    } finally {
      setBusy(false);
    }
  }

  async function setMemberRole(userId, newRole) {
    try {
      await changeMemberRole(userId, newRole);
      toast.success("Role updated");
      load();
    } catch (e) {
      const msg = e?.response?.data?.detail;
      if (msg && e?.response?.status === 400) toast.error(msg);
    }
  }

  async function remove(userId) {
    try {
      await removeMember(userId);
      toast.success("Member removed");
      load();
    } catch (e) {
      const msg = e?.response?.data?.detail;
      if (msg && e?.response?.status === 400) toast.error(msg);
    }
  }

  async function revoke(id) {
    try {
      await revokeInvite(id);
      load();
    } catch {
      /* handled globally */
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        data-testid="members-dialog"
        className="bg-[#0a0a0a] border border-[#222] rounded-none text-white max-w-lg"
      >
        <DialogHeader>
          <DialogTitle className="font-display font-bold tracking-tight flex items-center gap-2">
            <Users size={18} strokeWidth={1.5} />
            {data?.org?.name ? `${data.org.name} — TEAM` : "TEAM"}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div className="flex gap-2">
            <Input
              data-testid="invite-email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="colleague@council.gov.au"
              className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs focus-visible:ring-0 focus-visible:border-white"
            />
            <Select value={role} onValueChange={setRole}>
              <SelectTrigger
                data-testid="invite-role"
                className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs w-28 h-10 focus:ring-0"
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-[#0a0a0a] border-[#333] rounded-none text-white">
                {ROLES.map((r) => (
                  <SelectItem key={r} value={r} className="font-mono text-xs uppercase">
                    {r}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button
              data-testid="invite-submit"
              onClick={invite}
              disabled={busy}
              className="bg-white text-black hover:bg-[#00F5A0] rounded-none font-mono text-[10px] uppercase tracking-[0.15em] h-10 px-3"
            >
              {busy ? <Loader2 size={13} className="animate-spin" /> : <UserPlus size={13} />}
            </Button>
          </div>

          <div>
            <div className="text-[9px] font-mono uppercase tracking-[0.25em] text-[#666] mb-2">
              Members
            </div>
            <div className="space-y-1 max-h-56 overflow-y-auto" data-testid="members-list">
              {(data?.members || []).map((m) => (
                <div
                  key={m.user_id}
                  className="flex items-center justify-between gap-2 border border-[#1a1a1a] bg-[#0d0d0d] px-3 py-2"
                >
                  <div className="min-w-0">
                    <div className="font-mono text-xs text-white truncate">
                      {m.name || m.email}
                      {m.user_id === currentUserId && (
                        <span className="text-[#666] ml-1.5">(you)</span>
                      )}
                    </div>
                    <div className="font-mono text-[10px] text-[#666] truncate">{m.email}</div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <Select value={m.role} onValueChange={(r) => setMemberRole(m.user_id, r)}>
                      <SelectTrigger
                        data-testid={`member-role-${m.user_id}`}
                        className="bg-transparent border-[#333] rounded-none font-mono text-[10px] uppercase h-7 w-24 focus:ring-0"
                        style={{ color: ROLE_COLOR[m.role] || "#888" }}
                      >
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="bg-[#0a0a0a] border-[#333] rounded-none text-white">
                        {ROLES.map((r) => (
                          <SelectItem key={r} value={r} className="font-mono text-xs uppercase">
                            {r}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    {m.user_id !== currentUserId && (
                      <button
                        data-testid={`member-remove-${m.user_id}`}
                        onClick={() => remove(m.user_id)}
                        className="text-[#666] hover:text-[#FF3B30] transition-colors"
                        title="Remove member"
                      >
                        <Trash2 size={14} />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {(data?.invites || []).length > 0 && (
            <div>
              <div className="text-[9px] font-mono uppercase tracking-[0.25em] text-[#666] mb-2">
                Pending invites
              </div>
              <div className="space-y-1" data-testid="invites-list">
                {data.invites.map((i) => (
                  <div
                    key={i.id}
                    className="flex items-center justify-between gap-2 border border-dashed border-[#222] px-3 py-2"
                  >
                    <span className="font-mono text-xs text-[#aaa] truncate">{i.email}</span>
                    <span className="flex items-center gap-2 shrink-0">
                      <span
                        className="font-mono text-[9px] uppercase"
                        style={{ color: ROLE_COLOR[i.role] || "#888" }}
                      >
                        {i.role}
                      </span>
                      <button
                        data-testid={`invite-revoke-${i.id}`}
                        onClick={() => revoke(i.id)}
                        className="text-[#666] hover:text-[#FF3B30] transition-colors"
                        title="Revoke invite"
                      >
                        <MailX size={14} />
                      </button>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <p className="font-mono text-[10px] text-[#555] leading-relaxed">
            Invitees with an existing SentinelGrid account join instantly. Others join
            automatically when they first sign in with the invited email.
          </p>
        </div>
      </DialogContent>
    </Dialog>
  );
}
