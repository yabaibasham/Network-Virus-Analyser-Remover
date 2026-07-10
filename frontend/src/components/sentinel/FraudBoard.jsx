import { useEffect, useState } from "react";
import { Gavel, Loader2, Copy, FileText, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { submitFraudReport, fetchFraudReports } from "@/lib/api";
import { KIND_META } from "./CommunityWatch";
import { toast } from "sonner";

const EMPTY = {
  scheme_type: "bank_drop",
  perpetrator_alias: "",
  contact_indicators: "",
  jurisdictions: "",
  amount_estimate: "",
  victims_count: 1,
  narrative: "",
  evidence_urls: "",
  reporter_contact: "",
};

const toList = (s) =>
  (s || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);

export default function FraudBoard() {
  const [form, setForm] = useState(EMPTY);
  const [busy, setBusy] = useState(false);
  const [packet, setPacket] = useState(null);
  const [reports, setReports] = useState([]);
  const [copied, setCopied] = useState(false);

  const load = async () => setReports(await fetchFraudReports());
  useEffect(() => {
    load();
  }, []);

  const set = (k) => (v) => setForm((f) => ({ ...f, [k]: v?.target ? v.target.value : v }));

  async function submit() {
    if (!form.narrative.trim()) {
      toast.error("Describe what happened");
      return;
    }
    setBusy(true);
    try {
      const r = await submitFraudReport({
        scheme_type: form.scheme_type,
        perpetrator_alias: form.perpetrator_alias || null,
        contact_indicators: toList(form.contact_indicators),
        jurisdictions: toList(form.jurisdictions),
        amount_estimate: form.amount_estimate || null,
        victims_count: Number(form.victims_count) || 1,
        narrative: form.narrative,
        evidence_urls: toList(form.evidence_urls),
        reporter_contact: form.reporter_contact || null,
      });
      setPacket(r);
      toast.success(`Evidence packet ${r.case_ref} generated`);
      setForm(EMPTY);
      load();
    } catch {
      toast.error("Could not file report");
    } finally {
      setBusy(false);
    }
  }

  function copyPacket() {
    if (!packet?.evidence_packet) return;
    navigator.clipboard.writeText(packet.evidence_packet);
    setCopied(true);
    toast.success("Evidence packet copied");
    setTimeout(() => setCopied(false), 1600);
  }

  return (
    <div className="bg-[#0d0d0d] border border-[#222] fade-up" data-testid="fraud-board">
      <div className="flex items-center justify-between border-b border-[#222] px-4 py-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
            // FRAUD BOARD
          </div>
          <h2 className="font-display font-bold text-lg tracking-tight flex items-center gap-2">
            <Gavel size={16} strokeWidth={1.5} /> REPORT A FRAUDSTER
          </h2>
        </div>
        <span className="font-mono text-[10px] text-[#666]">{reports.length} filed</span>
      </div>

      <div className="p-4 space-y-3">
        <div className="grid grid-cols-2 gap-2">
          <Field label="SCHEME TYPE">
            <Select value={form.scheme_type} onValueChange={set("scheme_type")}>
              <SelectTrigger data-testid="fraud-scheme" className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs h-9 focus:ring-0">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-[#0a0a0a] border-[#333] rounded-none text-white">
                {Object.entries(KIND_META).map(([k, m]) => (
                  <SelectItem key={k} value={k} className="font-mono text-xs">{m.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field label="PERPETRATOR ALIAS">
            <Input data-testid="fraud-alias" value={form.perpetrator_alias} onChange={set("perpetrator_alias")}
              placeholder="'John from the bank'"
              className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs focus-visible:ring-0 focus-visible:border-white" />
          </Field>
        </div>
        <Field label="CONTACT INDICATORS (phone / email / handle / URL / account)">
          <Input data-testid="fraud-contacts" value={form.contact_indicators} onChange={set("contact_indicators")}
            placeholder="+1 202-555-0114, safe-account@mail.com, sortcode 04-00-04"
            className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs focus-visible:ring-0 focus-visible:border-white" />
        </Field>
        <div className="grid grid-cols-3 gap-2">
          <Field label="STATES / REGIONS">
            <Input data-testid="fraud-jurisdictions" value={form.jurisdictions} onChange={set("jurisdictions")}
              placeholder="TX, CA"
              className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs focus-visible:ring-0 focus-visible:border-white" />
          </Field>
          <Field label="EST. LOSS">
            <Input data-testid="fraud-amount" value={form.amount_estimate} onChange={set("amount_estimate")}
              placeholder="$4,200"
              className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs focus-visible:ring-0 focus-visible:border-white" />
          </Field>
          <Field label="VICTIMS">
            <Input data-testid="fraud-victims" type="number" min={1} value={form.victims_count} onChange={set("victims_count")}
              className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs focus-visible:ring-0 focus-visible:border-white" />
          </Field>
        </div>
        <Field label="WHAT HAPPENED">
          <textarea data-testid="fraud-narrative" value={form.narrative} onChange={set("narrative")}
            rows={3} placeholder="They called claiming to be the bank fraud team, spoofed the real number, and pressured me to move funds…"
            className="w-full bg-[#0a0a0a] border border-[#333] rounded-none font-mono text-xs p-2.5 focus:outline-none focus:border-white resize-none" />
        </Field>
        <div className="grid grid-cols-2 gap-2">
          <Field label="EVIDENCE LINKS">
            <Input data-testid="fraud-evidence" value={form.evidence_urls} onChange={set("evidence_urls")}
              placeholder="screenshot URLs"
              className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs focus-visible:ring-0 focus-visible:border-white" />
          </Field>
          <Field label="YOUR CONTACT (optional)">
            <Input data-testid="fraud-contact" value={form.reporter_contact} onChange={set("reporter_contact")}
              placeholder="for authorities only"
              className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs focus-visible:ring-0 focus-visible:border-white" />
          </Field>
        </div>
        <Button data-testid="fraud-submit" onClick={submit} disabled={busy}
          className="w-full bg-[#FF3B30] hover:bg-[#D62828] text-white rounded-none font-mono text-xs uppercase tracking-[0.2em] h-10">
          {busy ? <Loader2 size={14} className="animate-spin mr-2" /> : <FileText size={14} className="mr-2" />}
          GENERATE EVIDENCE PACKET
        </Button>

        {packet && (
          <div className="border border-[#222] bg-[#040404] mt-2" data-testid="evidence-packet">
            <div className="flex items-center justify-between border-b border-[#222] px-3 py-2">
              <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#00F5A0]">
                {packet.case_ref}
              </span>
              <button
                data-testid="copy-packet"
                onClick={copyPacket}
                className="flex items-center gap-1.5 font-mono text-[10px] uppercase border border-[#444] hover:border-white px-2 py-1 transition-colors"
              >
                {copied ? <Check size={11} className="text-[#00F5A0]" /> : <Copy size={11} />}
                {copied ? "copied" : "copy"}
              </button>
            </div>
            <pre className="p-3 font-mono text-[10.5px] text-[#cfcfcf] whitespace-pre-wrap leading-relaxed max-h-72 overflow-y-auto">
              {packet.evidence_packet}
            </pre>
          </div>
        )}

        {reports.length > 0 && (
          <div className="mt-2">
            <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666] mb-2">
              RECENT REPORTS
            </div>
            <div className="space-y-1">
              {reports.slice(0, 6).map((r) => (
                <button
                  key={r.id}
                  onClick={() => setPacket(r)}
                  className="w-full text-left border border-[#222] bg-[#0a0a0a] hover:bg-[#141414] px-3 py-2 flex items-center justify-between transition-colors"
                  data-testid={`fraud-report-${r.id}`}
                >
                  <span className="font-mono text-[11px] text-white">{r.case_ref}</span>
                  <span className="font-mono text-[10px] text-[#888] uppercase">
                    {(KIND_META[r.scheme_type] || KIND_META.other).label} · {r.victims_count}v
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}
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
