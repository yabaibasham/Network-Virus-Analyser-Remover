import { useEffect, useRef, useState } from "react";
import {
  Wrench,
  ShieldCheck,
  Loader2,
  Play,
  CheckCircle2,
  CircleDashed,
  Terminal,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { deviceIcon, DEVICE_META, STATUS_STYLES } from "@/lib/devices";
import { fetchDevices, remediateDevice, fetchRemediationJobs } from "@/lib/api";
import { toast } from "sonner";

export default function RemediationConsole({ onSelect, onChanged }) {
  const [devices, setDevices] = useState([]);
  const [jobs, setJobs] = useState([]);
  const [running, setRunning] = useState(null); // active job
  const [revealed, setRevealed] = useState(0);
  const [busyId, setBusyId] = useState(null);
  const timerRef = useRef(null);

  const load = async () => {
    const [d, j] = await Promise.all([fetchDevices(), fetchRemediationJobs()]);
    setDevices(d);
    setJobs(j);
  };

  useEffect(() => {
    load();
    return () => clearInterval(timerRef.current);
  }, []);

  const targets = devices.filter(
    (d) => d.status === "infected" || d.status === "quarantined" || d.threats_detected > 0
  );

  async function dispatch(dev) {
    setBusyId(dev.id);
    setRunning(null);
    setRevealed(0);
    try {
      const job = await remediateDevice(dev.id);
      setRunning(job);
      clearInterval(timerRef.current);
      let i = 0;
      timerRef.current = setInterval(() => {
        i += 1;
        setRevealed(i);
        if (i >= job.steps.length) {
          clearInterval(timerRef.current);
          toast.success(job.summary);
          load();
          onChanged?.();
        }
      }, 480);
    } catch {
      toast.error("Remediation failed to dispatch");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-3" data-testid="remediation-console">
      {/* Targets */}
      <div className="lg:col-span-5 bg-[#0d0d0d] border border-[#222] fade-up">
        <div className="border-b border-[#222] px-4 py-3">
          <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
            // AUTHORISED CLEAN-UP
          </div>
          <h2 className="font-display font-bold text-lg tracking-tight flex items-center gap-2">
            <Wrench size={16} strokeWidth={1.5} /> REMEDIATION DISPATCH
            <span className="font-mono text-xs text-[#666] ml-1">[{targets.length}]</span>
          </h2>
        </div>
        <div className="p-4 space-y-2 max-h-[520px] overflow-y-auto">
          <div className="text-[10px] font-mono text-[#666] border border-[#222] p-2 leading-relaxed">
            Runs only on devices in your consented fleet. Isolate → forensic snapshot →
            purge → re-attest. No action is taken on machines you do not own.
          </div>
          {targets.length === 0 && (
            <div className="font-mono text-xs text-[#00F5A0] py-4 flex items-center gap-2">
              <ShieldCheck size={14} /> fleet is clean · nothing to remediate
            </div>
          )}
          {targets.map((d) => {
            const Icon = deviceIcon(d.device_type);
            const st = STATUS_STYLES[d.status];
            return (
              <div
                key={d.id}
                className="border border-[#222] bg-[#0a0a0a] p-3"
                data-testid={`remediation-target-${d.id}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <button
                    onClick={() => onSelect?.(d.id)}
                    className="flex items-center gap-2 min-w-0 text-left"
                  >
                    <Icon size={16} strokeWidth={1.5} className="text-[#FF3B30] shrink-0" />
                    <div className="min-w-0">
                      <div className="font-mono text-xs text-white truncate">{d.hostname}</div>
                      <div className="font-mono text-[10px] text-[#888]">
                        {DEVICE_META[d.device_type]?.label} · {d.threats_detected} threat(s)
                      </div>
                    </div>
                  </button>
                  <span
                    className="font-mono text-[9px] uppercase border px-1.5 py-0.5 shrink-0"
                    style={{ color: st.color, borderColor: st.color + "66" }}
                  >
                    {st.label}
                  </span>
                </div>
                <Button
                  data-testid={`dispatch-${d.id}`}
                  onClick={() => dispatch(d)}
                  disabled={busyId === d.id || (running && revealed < running.steps.length)}
                  className="mt-2 w-full bg-white text-black hover:bg-[#00F5A0] rounded-none font-mono text-[10px] uppercase tracking-[0.2em] h-8"
                >
                  {busyId === d.id ? (
                    <Loader2 size={12} className="animate-spin mr-1.5" />
                  ) : (
                    <Play size={12} className="mr-1.5" />
                  )}
                  DISPATCH REMEDIATION
                </Button>
              </div>
            );
          })}
        </div>
      </div>

      {/* Console */}
      <div className="lg:col-span-7 bg-[#0d0d0d] border border-[#222] fade-up">
        <div className="border-b border-[#222] px-4 py-3 flex items-center gap-2">
          <Terminal size={15} strokeWidth={1.5} />
          <span className="font-mono text-xs uppercase tracking-[0.2em] text-[#888]">
            REMEDIATION CONSOLE
          </span>
          {running && (
            <span className="font-mono text-[10px] text-[#00F5A0] ml-auto">
              {running.device_hostname}
            </span>
          )}
        </div>
        <div className="scanlines p-4 font-mono text-[11px] min-h-[300px] max-h-[520px] overflow-y-auto">
          {!running && (
            <div className="text-[#666]">
              <span className="text-white">root@sentinel:~$</span> awaiting dispatch…{" "}
              <span className="blink text-white">▮</span>
            </div>
          )}
          {running &&
            running.steps.map((s, i) => {
              const shown = i < revealed;
              const active = i === revealed - 1 && revealed < running.steps.length;
              if (!shown) return null;
              return (
                <div key={i} className="flex gap-3 py-1 fade-up" data-testid={`remediation-step-${i}`}>
                  {revealed > i + 1 || revealed === running.steps.length ? (
                    <CheckCircle2 size={13} className="text-[#00F5A0] mt-0.5 shrink-0" />
                  ) : active ? (
                    <Loader2 size={13} className="text-[#FFCC00] mt-0.5 shrink-0 animate-spin" />
                  ) : (
                    <CircleDashed size={13} className="text-[#666] mt-0.5 shrink-0" />
                  )}
                  <span className="text-[#00F5A0] w-20 shrink-0 uppercase">{s.phase}</span>
                  <span className="text-[#ddd]">{s.detail}</span>
                </div>
              );
            })}
          {running && revealed >= running.steps.length && (
            <div className="mt-3 border border-[#00F5A0]/40 bg-[#04140d] p-3 text-[#00F5A0]" data-testid="remediation-summary">
              <ShieldCheck size={14} className="inline mr-2" />
              {running.summary}
            </div>
          )}
        </div>

        {jobs.length > 0 && (
          <div className="border-t border-[#222] p-3">
            <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666] mb-2">
              REMEDIATION HISTORY · {jobs.length}
            </div>
            <div className="space-y-1 max-h-32 overflow-y-auto">
              {jobs.map((j) => (
                <div
                  key={j.id}
                  className="flex items-center justify-between font-mono text-[11px] border border-[#222] bg-[#0a0a0a] px-3 py-1.5"
                >
                  <span className="text-white">{j.device_hostname}</span>
                  <span className="text-[#888]">{j.threats_removed} removed</span>
                  <span className="text-[#666]">{(j.created_at || "").slice(11, 19)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
