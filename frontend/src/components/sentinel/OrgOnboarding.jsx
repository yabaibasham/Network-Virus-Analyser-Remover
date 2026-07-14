import { useState } from "react";
import { Building2, ArrowRight, Loader2, LogOut, ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { createOrg, logout } from "@/lib/api";
import { toast } from "sonner";

const TYPES = [
  { v: "council", l: "Local Council" },
  { v: "agency", l: "Government Agency" },
  { v: "city", l: "City / Municipality" },
  { v: "fund", l: "Fund / Financial" },
  { v: "business", l: "Business" },
  { v: "other", l: "Other" },
];

export default function OrgOnboarding({ user, onCreated, onCancel }) {
  const [name, setName] = useState("");
  const [orgType, setOrgType] = useState("council");
  const [region, setRegion] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (!name.trim()) {
      toast.error("Give your organisation a name");
      return;
    }
    setBusy(true);
    try {
      const org = await createOrg({ name: name.trim(), org_type: orgType, region: region.trim() });
      toast.success(`${org.name} created — you're the Owner`);
      onCreated?.(org);
    } catch {
      toast.error("Could not create organisation");
    } finally {
      setBusy(false);
    }
  }

  const signOut = async () => {
    try { await logout(); } catch (e) { /* ignore */ }
    window.location.href = "/login";
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#050505] text-white relative overflow-hidden">
      <div className="radar-sweep" style={{ opacity: 0.2 }} />
      <div
        className="relative z-[2] w-full max-w-lg border border-[#222] bg-[#0a0a0a] p-8 fade-up"
        data-testid="org-onboarding"
      >
        <div className="flex items-center gap-3 mb-2">
          <Building2 size={24} strokeWidth={1.5} />
          <h1 className="font-display font-bold text-xl tracking-tight">
            CREATE YOUR ORGANISATION
          </h1>
        </div>
        <p className="text-[#aaa] text-sm mb-6 leading-relaxed">
          Welcome{user?.name ? `, ${user.name}` : ""}. Set up your organisation to isolate your
          fleet, alerts and team. You'll be the <span className="text-white">Owner</span> and can
          invite analysts and viewers.
        </p>

        <div className="space-y-3">
          <Field label="ORGANISATION NAME">
            <Input data-testid="org-name" value={name} onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Outback Shire Council"
              className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-sm focus-visible:ring-0 focus-visible:border-white" />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="TYPE">
              <Select value={orgType} onValueChange={setOrgType}>
                <SelectTrigger data-testid="org-type" className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs h-10 focus:ring-0">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-[#0a0a0a] border-[#333] rounded-none text-white">
                  {TYPES.map((t) => (
                    <SelectItem key={t.v} value={t.v} className="font-mono text-xs">{t.l}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <Field label="REGION">
              <Input data-testid="org-region" value={region} onChange={(e) => setRegion(e.target.value)}
                placeholder="NT / NSW / VIC…"
                className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs focus-visible:ring-0 focus-visible:border-white" />
            </Field>
          </div>
          <Button data-testid="org-create-btn" onClick={submit} disabled={busy}
            className="w-full bg-white text-black hover:bg-[#00F5A0] rounded-none font-mono text-xs uppercase tracking-[0.2em] h-11 mt-2">
            {busy ? <Loader2 size={14} className="animate-spin mr-2" /> : null}
            CREATE ORGANISATION <ArrowRight size={14} className="ml-2" />
          </Button>
          {onCancel ? (
            <button onClick={onCancel} data-testid="onboarding-back"
              className="w-full flex items-center justify-center gap-2 text-[#666] hover:text-white font-mono text-[10px] uppercase tracking-[0.2em] pt-2 transition-colors">
              <ArrowLeft size={12} /> back to dashboard
            </button>
          ) : (
            <button onClick={signOut} data-testid="onboarding-signout"
              className="w-full flex items-center justify-center gap-2 text-[#666] hover:text-white font-mono text-[10px] uppercase tracking-[0.2em] pt-2 transition-colors">
              <LogOut size={12} /> sign out
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <div>
      <label className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666] block mb-1">
        {label}
      </label>
      {children}
    </div>
  );
}
