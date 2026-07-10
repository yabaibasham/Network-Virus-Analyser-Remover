import { useEffect, useState } from "react";
import {
  Users,
  ShieldPlus,
  ThumbsUp,
  Loader2,
  Ban,
  Megaphone,
} from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  fetchCommunityAlerts,
  createCommunityAlert,
  corroborateAlert,
  fetchBlocklist,
} from "@/lib/api";
import { toast } from "sonner";

export const KIND_META = {
  scam: { label: "SCAM", color: "#FFCC00" },
  phishing: { label: "PHISHING", color: "#FF3B30" },
  malware_url: { label: "MALWARE URL", color: "#FF3B30" },
  keylogger: { label: "KEYLOGGER", color: "#FF3B30" },
  bank_drop: { label: "BANK DROP", color: "#FF3B30" },
  identity_theft: { label: "ID THEFT", color: "#FF3B30" },
  ransomware: { label: "RANSOMWARE", color: "#FF3B30" },
  spoofed_caller: { label: "SPOOF CALL", color: "#FFCC00" },
  other: { label: "OTHER", color: "#888888" },
};

const SEV_COLOR = { info: "#0044FF", warning: "#FFCC00", danger: "#FF3B30", critical: "#FF3B30" };

const EMPTY = {
  kind: "scam",
  severity: "warning",
  title: "",
  region: "Local Area",
  description: "",
  indicators: "",
  reporter_handle: "neighbour",
};

export default function CommunityWatch() {
  const [alerts, setAlerts] = useState([]);
  const [blocklist, setBlocklist] = useState({ count: 0, entries: [] });
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState(EMPTY);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    const [a, b] = await Promise.all([fetchCommunityAlerts(), fetchBlocklist()]);
    setAlerts(a);
    setBlocklist(b);
    setLoading(false);
  };

  useEffect(() => {
    load();
  }, []);

  async function submit() {
    if (!form.title.trim() || !form.description.trim()) {
      toast.error("Add a title and description");
      return;
    }
    setBusy(true);
    try {
      await createCommunityAlert({
        ...form,
        indicators: form.indicators
          .split(",")
          .map((x) => x.trim())
          .filter(Boolean),
      });
      toast.success("Alert broadcast to the neighbourhood watch");
      setOpen(false);
      setForm(EMPTY);
      load();
    } catch {
      toast.error("Could not file alert");
    } finally {
      setBusy(false);
    }
  }

  async function confirm(id) {
    try {
      const r = await corroborateAlert(id);
      toast.success(`Confirmed · ${r.corroborations} neighbours agree`);
      load();
    } catch {
      toast.error("Could not confirm");
    }
  }

  const set = (k) => (v) => setForm((f) => ({ ...f, [k]: v?.target ? v.target.value : v }));

  return (
    <div className="bg-[#0d0d0d] border border-[#222] fade-up" data-testid="community-watch">
      <div className="flex items-center justify-between border-b border-[#222] px-4 py-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
            // NEIGHBOURHOOD WATCH
          </div>
          <h2 className="font-display font-bold text-lg tracking-tight flex items-center gap-2">
            <Users size={16} strokeWidth={1.5} /> COMMUNITY WATCH
            <span className="font-mono text-xs text-[#666] ml-1">[{alerts.length}]</span>
          </h2>
        </div>
        <Button
          data-testid="report-alert-btn"
          onClick={() => setOpen(true)}
          className="bg-white text-black hover:bg-[#00F5A0] rounded-none font-mono text-[10px] uppercase tracking-[0.2em] h-8 px-3"
        >
          <Megaphone size={12} strokeWidth={1.5} className="mr-1.5" /> REPORT TO WATCH
        </Button>
      </div>

      <div className="p-4 space-y-3 max-h-[420px] overflow-y-auto">
        {loading && (
          <div className="font-mono text-xs text-[#666] py-4">loading neighbourhood feed…</div>
        )}
        {!loading &&
          alerts.map((a, idx) => {
            const km = KIND_META[a.kind] || KIND_META.other;
            return (
              <div
                key={a.id}
                className="border border-[#222] bg-[#0a0a0a] p-3"
                data-testid={`alert-card-${idx}`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className="font-mono text-[9px] uppercase tracking-wider border px-1.5 py-0.5"
                      style={{ color: km.color, borderColor: km.color + "66" }}
                    >
                      {km.label}
                    </span>
                    <span
                      className="font-mono text-[9px] uppercase tracking-wider"
                      style={{ color: SEV_COLOR[a.severity] }}
                    >
                      ● {a.severity}
                    </span>
                    <span className="font-mono text-[9px] text-[#666]">{a.region}</span>
                    {a.status === "verified" && (
                      <span className="font-mono text-[9px] uppercase text-[#00F5A0] border border-[#00F5A0]/50 px-1.5 py-0.5">
                        verified
                      </span>
                    )}
                  </div>
                </div>
                <div className="font-display font-bold text-sm mt-2 leading-tight">{a.title}</div>
                <p className="text-[#aaa] text-xs mt-1 leading-relaxed">{a.description}</p>
                {a.indicators?.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {a.indicators.map((ind, i) => (
                      <span
                        key={i}
                        className="font-mono text-[10px] text-[#FF9E9E] bg-[#1d0908] border border-[#3a1310] px-2 py-0.5 break-all"
                      >
                        {ind}
                      </span>
                    ))}
                  </div>
                )}
                <div className="mt-3 flex items-center justify-between">
                  <span className="font-mono text-[10px] text-[#666]">
                    by {a.reporter_handle} · {a.corroborations} confirmations
                  </span>
                  <button
                    data-testid={`corroborate-${idx}`}
                    onClick={() => confirm(a.id)}
                    className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.15em] border border-[#444] hover:border-white hover:bg-[#161616] px-2.5 py-1 transition-colors"
                  >
                    <ThumbsUp size={11} strokeWidth={1.5} /> confirm
                  </button>
                </div>
              </div>
            );
          })}
      </div>

      {/* Shared blocklist */}
      <div className="border-t border-[#222]">
        <div className="px-4 py-2.5 flex items-center gap-2 border-b border-[#222] bg-[#0a0a0a]">
          <Ban size={13} strokeWidth={1.5} className="text-[#FF3B30]" />
          <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#888]">
            SHARED BLOCKLIST
          </span>
          <span className="font-mono text-[10px] text-[#666] ml-auto">
            {blocklist.count} indicators
          </span>
        </div>
        <div className="p-3 max-h-40 overflow-y-auto font-mono text-[11px]" data-testid="blocklist">
          {blocklist.entries.length === 0 && (
            <div className="text-[#666]">no indicators shared yet</div>
          )}
          {blocklist.entries.map((e, i) => (
            <div key={i} className="flex items-center gap-2 py-0.5">
              <span className="text-[#FF3B30]">▸</span>
              <span className="text-[#ddd] break-all flex-1">{e.indicator}</span>
              <span className="text-[#666] uppercase text-[9px]">
                {(KIND_META[e.kind] || KIND_META.other).label} · {e.confirmations}✓
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Report dialog */}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent
          className="bg-[#0a0a0a] border border-[#222] rounded-none text-white max-w-lg"
          data-testid="report-alert-dialog"
        >
          <DialogHeader>
            <DialogTitle className="font-display tracking-tight uppercase flex items-center gap-2">
              <ShieldPlus size={16} /> Warn the neighbourhood
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3 mt-1">
            <div className="grid grid-cols-2 gap-2">
              <Field label="THREAT TYPE">
                <Select value={form.kind} onValueChange={set("kind")}>
                  <SelectTrigger data-testid="alert-kind" className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs h-9 focus:ring-0">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-[#0a0a0a] border-[#333] rounded-none text-white">
                    {Object.entries(KIND_META).map(([k, m]) => (
                      <SelectItem key={k} value={k} className="font-mono text-xs">
                        {m.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
              <Field label="SEVERITY">
                <Select value={form.severity} onValueChange={set("severity")}>
                  <SelectTrigger data-testid="alert-severity" className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs h-9 focus:ring-0">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-[#0a0a0a] border-[#333] rounded-none text-white">
                    {["info", "warning", "danger", "critical"].map((sv) => (
                      <SelectItem key={sv} value={sv} className="font-mono text-xs">
                        {sv.toUpperCase()}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
            </div>
            <Field label="TITLE">
              <Input data-testid="alert-title" value={form.title} onChange={set("title")}
                placeholder="Fake delivery text stealing card details"
                className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs focus-visible:ring-0 focus-visible:border-white" />
            </Field>
            <Field label="WHAT HAPPENED">
              <textarea data-testid="alert-description" value={form.description} onChange={set("description")}
                rows={3} placeholder="Describe the scam so neighbours can spot it…"
                className="w-full bg-[#0a0a0a] border border-[#333] rounded-none font-mono text-xs p-2.5 focus:outline-none focus:border-white resize-none" />
            </Field>
            <div className="grid grid-cols-2 gap-2">
              <Field label="REGION">
                <Input data-testid="alert-region" value={form.region} onChange={set("region")}
                  className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs focus-visible:ring-0 focus-visible:border-white" />
              </Field>
              <Field label="YOUR HANDLE">
                <Input data-testid="alert-handle" value={form.reporter_handle} onChange={set("reporter_handle")}
                  className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs focus-visible:ring-0 focus-visible:border-white" />
              </Field>
            </div>
            <Field label="INDICATORS (comma separated — URLs, numbers, handles)">
              <Input data-testid="alert-indicators" value={form.indicators} onChange={set("indicators")}
                placeholder="bad-site.top, +44 7700 900123, @scam_handle"
                className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs focus-visible:ring-0 focus-visible:border-white" />
            </Field>
          </div>
          <DialogFooter className="mt-2">
            <Button data-testid="alert-submit" onClick={submit} disabled={busy}
              className="bg-white text-black hover:bg-[#00F5A0] rounded-none font-mono text-xs uppercase tracking-[0.2em] h-10 w-full">
              {busy ? <Loader2 size={14} className="animate-spin mr-2" /> : null}
              BROADCAST ALERT
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
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
