import { useRef, useState } from "react";
import { Crosshair, Upload, Loader2, Link2, FileText } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { runScan, uploadScan } from "@/lib/api";
import { toast } from "sonner";

const VERDICT_STYLES = {
  clean:      { color: "#0044FF", label: "CLEAN" },
  suspicious: { color: "#FFCC00", label: "SUSPICIOUS" },
  malicious:  { color: "#FF3B30", label: "MALICIOUS" },
};

function VerdictPanel({ result }) {
  if (!result) return null;
  const v = VERDICT_STYLES[result.verdict];
  return (
    <div
      className="border border-[#222] bg-[#0a0a0a] mt-3"
      data-testid="scan-verdict"
    >
      <div
        className="px-3 py-2 flex items-center justify-between border-b border-[#222]"
        style={{ borderColor: v.color + "55" }}
      >
        <div className="flex items-center gap-2">
          <span className="status-dot" style={{ background: v.color }} />
          <span
            className="font-display font-bold text-lg tracking-tight"
            style={{ color: v.color }}
            data-testid="verdict-label"
          >
            {v.label}
          </span>
        </div>
        <div className="font-mono text-xs text-[#888]">
          RISK <span className="text-white text-base" data-testid="risk-score">{result.risk_score}</span>/100
        </div>
      </div>

      <div className="px-3 py-2 border-b border-[#222]">
        <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666] mb-1">TARGET</div>
        <div className="font-mono text-[11px] text-[#ddd] break-all">
          {result.filename ? `[${result.filename}] ` : ""}
          {result.target.length > 200 ? result.target.slice(0, 200) + "…" : result.target}
        </div>
      </div>

      <div className="px-3 py-2 border-b border-[#222]">
        <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666] mb-1">AI REASONING</div>
        <div className="text-xs text-[#ccc] leading-relaxed">{result.ai_reasoning}</div>
      </div>

      <div className="px-3 py-2 border-b border-[#222]">
        <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666] mb-1">
          IOCs ({result.iocs.length})
        </div>
        <ul className="space-y-0.5">
          {result.iocs.map((i, idx) => (
            <li key={idx} className="font-mono text-[11px] text-[#ddd]">
              <span className="text-[#FF3B30]">▸</span> {i}
            </li>
          ))}
        </ul>
      </div>

      <div className="px-3 py-2">
        <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666] mb-1">
          RECOMMENDED ACTIONS
        </div>
        <ul className="space-y-0.5">
          {result.recommended_actions.map((a, idx) => (
            <li key={idx} className="font-mono text-[11px] text-[#fff]">
              <span className="text-[#00F5A0]">→</span> {a}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function ProgressLine({ active }) {
  if (!active) return null;
  return (
    <div className="mt-3 font-mono text-[11px] text-[#888]" data-testid="scan-progress">
      <div className="flex items-center gap-2">
        <Loader2 size={12} className="animate-spin text-[#FFCC00]" />
        <span>STREAM://heuristic-engine</span>
        <span className="text-white">running</span>
        <span className="blink text-white">▮</span>
      </div>
      <div className="mt-2 text-[#666]">
        ▸ Lexical IOC pass<br />
        ▸ Reputation surface<br />
        ▸ AI heuristic (claude-sonnet-4-6)<br />
        ▸ Composite verdict
      </div>
    </div>
  );
}

export default function ScannerWidget({ onScanDone }) {
  const [tab, setTab] = useState("url");
  const [url, setUrl] = useState("");
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const fileRef = useRef(null);

  async function handleUrl() {
    if (!url.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const r = await runScan({ target_type: "url", target: url.trim() });
      setResult(r);
      toast.success(`Scan complete · ${r.verdict.toUpperCase()} · ${r.risk_score}/100`);
      onScanDone?.();
    } catch (e) {
      toast.error("Scan failed: " + (e?.message || "unknown"));
    } finally {
      setLoading(false);
    }
  }

  async function handleText() {
    if (!text.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const r = await runScan({ target_type: "file_text", target: text });
      setResult(r);
      toast.success(`Scan complete · ${r.verdict.toUpperCase()} · ${r.risk_score}/100`);
      onScanDone?.();
    } catch (e) {
      toast.error("Scan failed: " + (e?.message || "unknown"));
    } finally {
      setLoading(false);
    }
  }

  async function handleFile(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    setLoading(true);
    setResult(null);
    try {
      const r = await uploadScan(f);
      setResult(r);
      toast.success(`Scan complete · ${r.verdict.toUpperCase()} · ${r.risk_score}/100`);
      onScanDone?.();
    } catch (err) {
      toast.error("Upload failed: " + (err?.message || "unknown"));
    } finally {
      setLoading(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  const tabs = [
    { id: "url",  label: "URL",  Icon: Link2 },
    { id: "file", label: "FILE", Icon: Upload },
    { id: "text", label: "PASTE", Icon: FileText },
  ];

  return (
    <div className="bg-[#0d0d0d] border border-[#222]" data-testid="scanner-widget">
      <div className="flex items-center justify-between border-b border-[#222] px-4 py-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">// SECTION 02</div>
          <h2 className="font-display font-bold text-lg tracking-tight flex items-center gap-2">
            <Crosshair size={16} strokeWidth={1.5} /> HEURISTIC SCANNER
          </h2>
        </div>
      </div>

      <div className="flex border-b border-[#222] bg-[#0a0a0a]">
        {tabs.map(({ id, label, Icon }) => (
          <button
            key={id}
            data-testid={`scan-tab-${id}`}
            onClick={() => setTab(id)}
            className={`flex-1 flex items-center justify-center gap-2 px-3 py-2.5 font-mono text-[10px] uppercase tracking-[0.2em] border-r border-[#222] last:border-r-0 transition-colors ${
              tab === id
                ? "bg-white text-black"
                : "text-[#888] hover:text-white hover:bg-[#161616]"
            }`}
          >
            <Icon size={12} strokeWidth={1.5} />
            {label}
          </button>
        ))}
      </div>

      <div className="p-4 space-y-3">
        {tab === "url" && (
          <>
            <label className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
              TARGET URL
            </label>
            <Input
              data-testid="scan-url-input"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://suspicious.example.tk/wallet-verify"
              className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs focus-visible:ring-0 focus-visible:border-white"
              onKeyDown={(e) => e.key === "Enter" && handleUrl()}
            />
            <Button
              data-testid="scan-url-submit"
              onClick={handleUrl}
              disabled={loading || !url.trim()}
              className="w-full bg-white text-black hover:bg-[#00F5A0] rounded-none font-mono text-xs uppercase tracking-[0.2em] h-10"
            >
              {loading ? <Loader2 size={14} className="animate-spin mr-2" /> : null}
              EXECUTE SCAN
            </Button>
          </>
        )}

        {tab === "file" && (
          <>
            <label
              className="block border-2 border-dashed border-[#333] hover:border-white transition-colors p-6 text-center cursor-pointer"
              data-testid="scan-file-dropzone"
            >
              <input
                ref={fileRef}
                type="file"
                className="hidden"
                onChange={handleFile}
                data-testid="scan-file-input"
              />
              <Upload size={20} strokeWidth={1.5} className="mx-auto text-[#888] mb-2" />
              <div className="font-mono text-xs text-white">DROP / CLICK TO UPLOAD</div>
              <div className="font-mono text-[10px] text-[#666] mt-1">
                hash + first-6KB heuristic analysis
              </div>
            </label>
          </>
        )}

        {tab === "text" && (
          <>
            <label className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
              PASTE PAYLOAD / SNIPPET
            </label>
            <textarea
              data-testid="scan-text-input"
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={5}
              placeholder="powershell -enc JABzAD0A... or curl http://... | sh"
              className="w-full bg-[#0a0a0a] border border-[#333] rounded-none font-mono text-xs p-3 focus:outline-none focus:border-white resize-none"
            />
            <Button
              data-testid="scan-text-submit"
              onClick={handleText}
              disabled={loading || !text.trim()}
              className="w-full bg-white text-black hover:bg-[#00F5A0] rounded-none font-mono text-xs uppercase tracking-[0.2em] h-10"
            >
              {loading ? <Loader2 size={14} className="animate-spin mr-2" /> : null}
              EXECUTE SCAN
            </Button>
          </>
        )}

        <ProgressLine active={loading} />
        <VerdictPanel result={result} />
      </div>
    </div>
  );
}
