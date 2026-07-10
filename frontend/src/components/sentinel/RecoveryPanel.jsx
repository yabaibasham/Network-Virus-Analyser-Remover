import { useState } from "react";
import { MapPin, AlertOctagon, CheckCircle2, Loader2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { reportMissing, markRecovered } from "@/lib/api";
import { deviceIcon, DEVICE_META } from "@/lib/devices";
import { toast } from "sonner";

const RECOVERY_STEPS = [
  "Notify carrier / fleet manager",
  "Trigger remote lock via MDM if enrolled",
  "Preserve network + auth logs as evidence",
  "File incident with local law enforcement",
  "Revoke device credentials & rotate keys",
];

function MissingTag({ status }) {
  if (status === "missing")
    return (
      <span
        className="inline-flex items-center gap-1.5 border border-[#FF3B30]/55 text-[#FF3B30] px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider danger-pulse"
        data-testid="missing-tag"
      >
        <span className="status-dot" style={{ background: "#FF3B30" }} />
        MISSING
      </span>
    );
  if (status === "recovered")
    return (
      <span className="inline-flex items-center gap-1.5 border border-[#00F5A0]/55 text-[#00F5A0] px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider">
        <span className="status-dot" style={{ background: "#00F5A0" }} />
        RECOVERED
      </span>
    );
  return null;
}

export default function RecoveryPanel({ devices, onChanged }) {
  const [open, setOpen] = useState(false);
  const [targetId, setTargetId] = useState("");
  const [lat, setLat] = useState("");
  const [lon, setLon] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const missing = devices.filter((d) => d.missing_status === "missing");
  const recovered = devices.filter((d) => d.missing_status === "recovered");

  async function submit() {
    if (!targetId) {
      toast.error("Pick a device");
      return;
    }
    setBusy(true);
    try {
      await reportMissing(targetId, {
        last_lat: lat ? Number(lat) : null,
        last_lon: lon ? Number(lon) : null,
        accuracy_m: 100,
        note: note || null,
      });
      toast.success("Device flagged MISSING. Recovery playbook armed.");
      setOpen(false);
      setTargetId("");
      setLat("");
      setLon("");
      setNote("");
      onChanged?.();
    } catch (e) {
      toast.error("Could not flag device.");
    } finally {
      setBusy(false);
    }
  }

  async function recover(id) {
    setBusy(true);
    try {
      await markRecovered(id);
      toast.success("Device marked RECOVERED.");
      onChanged?.();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="bg-[#0d0d0d] border border-[#222]" data-testid="recovery-panel">
      <div className="flex items-center justify-between border-b border-[#222] px-4 py-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
            // SECTION 04
          </div>
          <h2 className="font-display font-bold text-lg tracking-tight flex items-center gap-2">
            <MapPin size={16} strokeWidth={1.5} />
            ASSET RECOVERY
          </h2>
        </div>
        <Button
          data-testid="report-missing-btn"
          onClick={() => setOpen(true)}
          className="bg-[#FF3B30] hover:bg-[#D62828] text-white rounded-none font-mono text-[10px] uppercase tracking-[0.2em] h-8 px-3"
        >
          <AlertOctagon size={12} strokeWidth={1.5} className="mr-1.5" />
          REPORT MISSING
        </Button>
      </div>

      <div className="p-4 space-y-3">
        <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666] mb-2">
          ACTIVE INCIDENTS · {missing.length}
        </div>
        {missing.length === 0 && (
          <div className="font-mono text-xs text-[#666] py-2">
            no missing devices · all assets accounted for
          </div>
        )}
        {missing.map((d) => {
          const Icon = deviceIcon(d.device_type);
          const loc = d.last_known_location;
          return (
            <div
              key={d.id}
              className="border border-[#222] bg-[#0a0a0a] p-3"
              data-testid={`missing-card-${d.id}`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-start gap-2 min-w-0">
                  <Icon size={16} strokeWidth={1.5} className="text-[#FF3B30] mt-0.5 shrink-0" />
                  <div className="min-w-0">
                    <div className="font-mono text-xs text-white truncate">
                      {d.hostname}
                    </div>
                    <div className="font-mono text-[10px] text-[#888]">
                      {DEVICE_META[d.device_type]?.label}
                    </div>
                  </div>
                </div>
                <MissingTag status="missing" />
              </div>

              {loc && (
                <div className="mt-3 border border-[#1a1a1a] bg-[#070707] p-2 font-mono text-[11px]">
                  <div className="text-[#666] uppercase text-[9px] tracking-[0.2em] mb-1">
                    LAST KNOWN POSITION · {loc.source}
                  </div>
                  <div className="text-white">
                    {loc.lat.toFixed(5)}, {loc.lon.toFixed(5)}
                  </div>
                  <div className="text-[#888] text-[10px]">
                    ±{loc.accuracy_m}m · {(loc.reported_at || "").slice(0, 19).replace("T", " ")}
                  </div>
                  <a
                    href={`https://www.openstreetmap.org/?mlat=${loc.lat}&mlon=${loc.lon}#map=12/${loc.lat}/${loc.lon}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    data-testid={`map-link-${d.id}`}
                    className="inline-block mt-1 text-[#00F5A0] hover:underline text-[11px]"
                  >
                    ▸ open in map
                  </a>
                </div>
              )}

              <div className="mt-3 space-y-1">
                {RECOVERY_STEPS.map((s, idx) => (
                  <div
                    key={idx}
                    className="font-mono text-[11px] text-[#ccc] flex items-start gap-1.5"
                  >
                    <span className="text-[#666]">{String(idx + 1).padStart(2, "0")}</span>
                    {s}
                  </div>
                ))}
              </div>

              <Button
                data-testid={`mark-recovered-${d.id}`}
                onClick={() => recover(d.id)}
                disabled={busy}
                className="mt-3 w-full bg-white text-black hover:bg-[#00F5A0] rounded-none font-mono text-[10px] uppercase tracking-[0.2em] h-8"
              >
                <CheckCircle2 size={12} strokeWidth={1.5} className="mr-1.5" />
                MARK RECOVERED
              </Button>
            </div>
          );
        })}

        {recovered.length > 0 && (
          <>
            <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666] mt-4 mb-2">
              RECENTLY RECOVERED · {recovered.length}
            </div>
            {recovered.map((d) => {
              const Icon = deviceIcon(d.device_type);
              return (
                <div
                  key={d.id}
                  className="border border-[#222] bg-[#0a0a0a] p-2 flex items-center justify-between"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <Icon size={14} strokeWidth={1.5} className="text-[#00F5A0] shrink-0" />
                    <span className="font-mono text-xs truncate">{d.hostname}</span>
                  </div>
                  <MissingTag status="recovered" />
                </div>
              );
            })}
          </>
        )}
      </div>

      {/* Report missing modal */}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent
          className="bg-[#0a0a0a] border border-[#222] rounded-none text-white max-w-md"
          data-testid="report-missing-dialog"
        >
          <DialogHeader>
            <DialogTitle className="font-display tracking-tight uppercase">
              Flag device as missing
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-3 mt-2">
            <div>
              <label className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
                DEVICE
              </label>
              <Select value={targetId} onValueChange={setTargetId}>
                <SelectTrigger
                  data-testid="missing-device-select"
                  className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs h-10 mt-1 focus:ring-0"
                >
                  <SelectValue placeholder="pick a device" />
                </SelectTrigger>
                <SelectContent className="bg-[#0a0a0a] border-[#333] rounded-none text-white">
                  {devices
                    .filter((d) => d.missing_status !== "missing")
                    .map((d) => (
                      <SelectItem
                        key={d.id}
                        value={d.id}
                        className="font-mono text-xs"
                      >
                        {d.hostname} · {DEVICE_META[d.device_type]?.label}
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
                  LAST LAT (optional)
                </label>
                <Input
                  data-testid="missing-lat"
                  value={lat}
                  onChange={(e) => setLat(e.target.value)}
                  placeholder="48.21645"
                  className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs mt-1 focus-visible:ring-0 focus-visible:border-white"
                />
              </div>
              <div>
                <label className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
                  LAST LON (optional)
                </label>
                <Input
                  data-testid="missing-lon"
                  value={lon}
                  onChange={(e) => setLon(e.target.value)}
                  placeholder="16.37230"
                  className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs mt-1 focus-visible:ring-0 focus-visible:border-white"
                />
              </div>
            </div>

            <div>
              <label className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
                NOTE
              </label>
              <Input
                data-testid="missing-note"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="left in cab, last seen at airport…"
                className="bg-[#0a0a0a] border-[#333] rounded-none font-mono text-xs mt-1 focus-visible:ring-0 focus-visible:border-white"
              />
            </div>

            <div className="text-[10px] font-mono text-[#666] leading-relaxed border border-[#222] p-2">
              Coordinates are owner-supplied or last self-reported by the device agent.
              SentinelGrid does not perform covert geolocation.
            </div>
          </div>

          <DialogFooter className="mt-2">
            <Button
              data-testid="missing-submit"
              onClick={submit}
              disabled={busy || !targetId}
              className="bg-[#FF3B30] hover:bg-[#D62828] text-white rounded-none font-mono text-xs uppercase tracking-[0.2em] h-10 w-full"
            >
              {busy ? <Loader2 size={14} className="animate-spin mr-2" /> : null}
              FLAG MISSING
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
