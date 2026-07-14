"""Heuristic scanner: static IOC pass + AI triage + real threat intel.

Threat-intel engines:
  - CIRCL hashlookup (govCERT-LU) — keyless file/hash reputation
  - ClamAV — local open-source signature engine (uploaded file bytes)
  - VirusTotal — optional, enabled only when VT_API_KEY is present
"""
import os
import re
import glob
import json
import uuid
import base64
import shutil
import hashlib
import asyncio
import tempfile
import time
from collections import defaultdict, deque
from typing import List, Optional, Dict, Any

import httpx
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends

from emergentintegrations.llm.chat import LlmChat, UserMessage

from database import db, now_iso, log, EMERGENT_LLM_KEY, VT_API_KEY
from models import ScanRequest, ScanResult
from events import _log_event
from context import get_current_context, ensure_write

router = APIRouter()

# Per-user sliding-window rate limit on paid/costly scan endpoints (SEC-003)
SCAN_RATE_LIMIT_PER_MIN = 10
_scan_hits: Dict[str, deque] = defaultdict(deque)


def _enforce_scan_rate(user_id: str):
    now = time.monotonic()
    q = _scan_hits[user_id]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= SCAN_RATE_LIMIT_PER_MIN:
        raise HTTPException(429, "Scan rate limit reached (10/min) — try again shortly")
    q.append(now)

CLAM_DB_DIR = "/var/lib/clamav"


def _clamscan_bin() -> Optional[str]:
    return shutil.which("clamscan")

SUSPICIOUS_TLDS = {".ru", ".tk", ".top", ".xyz", ".click", ".zip", ".country"}
SUSPICIOUS_TERMS = [
    "powershell -enc", "base64", "rundll32", "mimikatz", "cobalt", "metasploit",
    "njrat", "darkcomet", "quasar", "asyncrat", "netwire", "remcos", "agenttesla",
    "wget http", "curl http", "/tmp/.x", "chmod 777", "nc -e", "reverse shell",
    "eval(", "exec(", "child_process", "registry add", "schtasks /create",
]


def _local_ioc_scan(target_type: str, target: str) -> dict:
    iocs = []
    score = 5
    categories = []
    t = target.lower()
    if target_type == "url":
        for tld in SUSPICIOUS_TLDS:
            if tld in t:
                iocs.append(f"Suspicious TLD: {tld}")
                score += 25
                categories.append("URL-Reputation")
        if re.search(r"\d{1,3}(\.\d{1,3}){3}", t):
            iocs.append("Raw IPv4 hostname")
            score += 15
            categories.append("URL-Reputation")
        host_part = t.split("://", 1)[-1].split("/", 1)[0]
        if "@" in host_part:
            iocs.append("Embedded credentials in host")
            score += 20
        if any(k in t for k in ["login", "verify", "wallet", "secure", "update"]):
            iocs.append("Phishing keyword in path")
            score += 10
            categories.append("Phishing")
    else:
        for term in SUSPICIOUS_TERMS:
            if term in t:
                iocs.append(f"Suspicious token: {term}")
                score += 18
                categories.append("Malware-Heuristic")
    score = min(100, score)
    return {"iocs": iocs, "score": score, "categories": list(dict.fromkeys(categories)) or ["Unclassified"]}


async def _ai_heuristic(target_type: str, target: str, local: dict) -> dict:
    if not EMERGENT_LLM_KEY:
        return {
            "reasoning": "AI heuristic engine offline (no key). Falling back to static IOC scoring.",
            "verdict_score_adjust": 0,
            "recommended_actions": ["Block target", "Monitor endpoints", "Open incident ticket"],
        }

    system = (
        "You are SENTINEL-CORE, a strict malware-triage analyst. "
        "Given a target (URL/file-hash/file-content snippet) and the IOC findings, "
        "respond with a SINGLE JSON object — no prose, no markdown — with keys: "
        "reasoning (string, <= 90 words, terse SOC tone), "
        "verdict_score_adjust (int -20..+30, how much to shift the risk score), "
        "recommended_actions (array of 3-5 short imperative strings)."
    )
    payload = {
        "target_type": target_type,
        "target": target[:2000],
        "local_iocs": local["iocs"],
        "current_score": local["score"],
        "categories": local["categories"],
    }
    try:
        chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=f"scan-{uuid.uuid4()}",
            system_message=system,
        ).with_model("anthropic", "claude-sonnet-4-6")
        msg = UserMessage(text=json.dumps(payload))
        reply = await chat.send_message(msg)
        text = reply if isinstance(reply, str) else getattr(reply, "content", str(reply))
        match = re.search(r"\{.*\}", text, re.S)
        data = json.loads(match.group(0)) if match else {}
        return {
            "reasoning": data.get("reasoning", "No reasoning produced."),
            "verdict_score_adjust": int(data.get("verdict_score_adjust", 0)),
            "recommended_actions": data.get("recommended_actions", []) or [
                "Block target at egress", "Isolate impacted host", "Notify on-call"
            ],
        }
    except Exception as e:
        log.warning("AI heuristic failed: %s", e)
        return {
            "reasoning": f"AI heuristic unavailable ({type(e).__name__}). Using static IOC-only triage.",
            "verdict_score_adjust": 0,
            "recommended_actions": ["Block target", "Isolate host", "Open incident"],
        }


async def _virustotal_lookup(target_type: str, target: str) -> Optional[Dict[str, Any]]:
    if not VT_API_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=15) as h:
            if target_type == "url":
                vt_id = base64.urlsafe_b64encode(target.strip().encode()).rstrip(b"=").decode()
                r = await h.get(
                    f"https://www.virustotal.com/api/v3/urls/{vt_id}",
                    headers={"x-apikey": VT_API_KEY},
                )
                if r.status_code == 404:
                    return {"status": "not_indexed", "engines_malicious": 0}
                if r.status_code != 200:
                    return {"status": f"vt_error_{r.status_code}"}
                data = r.json().get("data", {}).get("attributes", {})
            elif target_type == "file_hash":
                r = await h.get(
                    f"https://www.virustotal.com/api/v3/files/{target.strip()}",
                    headers={"x-apikey": VT_API_KEY},
                )
                if r.status_code == 404:
                    return {"status": "not_indexed", "engines_malicious": 0}
                if r.status_code != 200:
                    return {"status": f"vt_error_{r.status_code}"}
                data = r.json().get("data", {}).get("attributes", {})
            else:
                return None
            stats = data.get("last_analysis_stats", {})
            return {
                "status": "indexed",
                "engines_malicious": stats.get("malicious", 0),
                "engines_suspicious": stats.get("suspicious", 0),
                "engines_harmless": stats.get("harmless", 0),
                "engines_total": sum(stats.values()) if stats else 0,
                "reputation": data.get("reputation", 0),
            }
    except Exception as e:
        log.warning("VT lookup failed: %s", e)
        return {"status": f"vt_exception:{type(e).__name__}"}


def _verdict_from_score(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score >= 35:
        return "suspicious"
    return "clean"


# --- CIRCL hashlookup (govCERT-LU) — keyless file/hash reputation ---
async def _circl_hashlookup(h: Optional[str]) -> Optional[Dict[str, Any]]:
    if not h:
        return None
    h = h.strip()
    algo = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h))
    if not algo or not re.fullmatch(r"[0-9a-fA-F]+", h):
        return {"status": "unsupported_hash", "source": "CIRCL hashlookup"}
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(
                f"https://hashlookup.circl.lu/lookup/{algo}/{h}",
                headers={"accept": "application/json"},
            )
        if r.status_code == 404:
            return {"status": "unknown", "source": "CIRCL hashlookup (govCERT-LU)",
                    "note": "Hash not in any known dataset (NSRL / distros / malware feeds)."}
        if r.status_code != 200:
            return {"status": f"error_{r.status_code}", "source": "CIRCL hashlookup"}
        d = r.json()
        trust = d.get("hashlookup:trust")
        known_malicious = bool(
            d.get("KnownMalicious") or d.get("malicious")
            or (isinstance(trust, int) and trust <= 20)
        )
        return {
            "status": "known",
            "source": "CIRCL hashlookup (govCERT-LU)",
            "filename": d.get("FileName") or d.get("filename") or d.get("SHA-256"),
            "trust": trust,
            "known_malicious": known_malicious,
            "dataset": d.get("source") or d.get("db") or "NSRL / distro / community",
        }
    except Exception as e:
        log.warning("CIRCL lookup failed: %s", e)
        return {"status": f"exception:{type(e).__name__}", "source": "CIRCL hashlookup"}


# --- ClamAV — local open-source signature scan of uploaded bytes ---
def _clam_db_ready() -> bool:
    return bool(glob.glob(f"{CLAM_DB_DIR}/*.cvd") or glob.glob(f"{CLAM_DB_DIR}/*.cld"))


def clamav_status() -> str:
    if not _clamscan_bin():
        return "unavailable"
    return "ready" if _clam_db_ready() else "updating"


async def bootstrap_clamav():
    """Self-heal ClamAV on cold start (runtime apt installs don't persist).

    Non-blocking best-effort: installs the engine and/or refreshes signatures in
    the background. The scanner degrades gracefully while this runs.
    """
    try:
        if _clamscan_bin() and _clam_db_ready():
            return
        if not _clamscan_bin():
            log.info("ClamAV: bootstrapping engine + signatures in background …")
            cmd = ("apt-get install -y clamav clamav-freshclam "
                   "&& (systemctl stop clamav-freshclam 2>/dev/null; freshclam)")
        else:
            log.info("ClamAV: refreshing signature database in background …")
            cmd = "systemctl stop clamav-freshclam 2>/dev/null; freshclam"
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.communicate()
        log.info("ClamAV bootstrap finished · status=%s", clamav_status())
    except Exception as e:
        log.warning("ClamAV bootstrap skipped: %s", e)


async def _clamav_scan_path(path: str) -> Dict[str, Any]:
    binary = _clamscan_bin()
    if not binary:
        return {"status": "unavailable", "engine": "ClamAV",
                "note": "Signature engine bootstrapping; unavailable right now."}
    if not _clam_db_ready():
        return {"status": "db_updating", "engine": "ClamAV",
                "note": "Signature database is still downloading; try again shortly."}
    try:
        proc = await asyncio.create_subprocess_exec(
            binary, "--no-summary", "--stdout", path,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await proc.communicate()
        text = out.decode(errors="ignore").strip()
        if proc.returncode == 1:
            sig = "malware"
            if ":" in text:
                sig = text.split(":", 1)[1].replace("FOUND", "").strip() or sig
            return {"status": "scanned", "engine": "ClamAV", "infected": True, "signature": sig}
        if proc.returncode == 0:
            return {"status": "scanned", "engine": "ClamAV", "infected": False}
        return {"status": "error", "engine": "ClamAV", "detail": text[:160]}
    except Exception as e:
        log.warning("ClamAV scan failed: %s", e)
        return {"status": f"exception:{type(e).__name__}", "engine": "ClamAV"}


def _hash_for_lookup(req: ScanRequest) -> Optional[str]:
    if req.file_sha256:
        return req.file_sha256
    if req.target_type == "file_hash":
        return req.target.strip()
    return None


async def _perform_scan(req: ScanRequest, clam_path: Optional[str] = None,
                        org_id: Optional[str] = None) -> ScanResult:
    local = _local_ioc_scan(req.target_type, req.target)
    ai = await _ai_heuristic(req.target_type, req.target, local)
    vt = await _virustotal_lookup(req.target_type, req.target)
    circl = await _circl_hashlookup(_hash_for_lookup(req))
    clam = await _clamav_scan_path(clam_path) if clam_path else None

    score = local["score"] + ai["verdict_score_adjust"]
    iocs = list(local["iocs"])
    categories = list(local["categories"])

    if vt and vt.get("engines_malicious"):
        score += min(30, int(vt["engines_malicious"]) * 5)
        iocs.append(f"VirusTotal: {vt['engines_malicious']} engines flagged malicious")
        categories.append("Threat-Intel")

    if circl:
        if circl.get("known_malicious"):
            score = max(score, 90)
            iocs.append("CIRCL hashlookup: known-malicious file hash")
            categories.append("Threat-Intel")
        elif circl.get("status") == "known" and not circl.get("known_malicious"):
            # A hash the govCERT dataset recognises as legitimate software
            score = min(score, 10)
            iocs.append(f"CIRCL hashlookup: known-good file ({circl.get('dataset')})")

    if clam and clam.get("infected"):
        score = 100
        iocs.append(f"ClamAV signature match: {clam.get('signature')}")
        categories.append("Signature-Match")

    final_score = max(0, min(100, score))
    verdict = _verdict_from_score(final_score)

    result = ScanResult(
        target_type=req.target_type,
        target=req.target,
        filename=req.filename,
        verdict=verdict,  # type: ignore[arg-type]
        risk_score=final_score,
        iocs=iocs or ["No static IOCs matched"],
        categories=list(dict.fromkeys(categories)) or ["Unclassified"],
        ai_reasoning=ai["reasoning"],
        recommended_actions=ai["recommended_actions"],
        vt_summary=vt,
        circl_summary=circl,
        clamav_summary=clam,
        org_id=org_id,
    )
    await db.scan_results.insert_one(result.model_dump())

    sev = {"malicious": "critical", "suspicious": "warning", "clean": "info"}[verdict]
    label = req.filename or req.target
    await _log_event(sev, "SCAN", f"{verdict.upper()} · score {final_score}/100 · {label[:80]}",
                     org_id=org_id)
    return result


@router.post("/scan", response_model=ScanResult)
async def run_scan(req: ScanRequest, ctx=Depends(get_current_context)):
    ensure_write(ctx)
    _enforce_scan_rate(ctx["user"].user_id)
    return await _perform_scan(req, org_id=ctx["org_id"])


@router.post("/scan/upload", response_model=ScanResult)
async def scan_upload(file: UploadFile = File(...), ctx=Depends(get_current_context)):
    ensure_write(ctx)
    _enforce_scan_rate(ctx["user"].user_id)
    max_bytes = 1024 * 1024 * 1024  # 1 GB cap
    h = hashlib.sha256()
    total = 0
    head = b""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    try:
        while True:
            chunk = await file.read(1024 * 1024)  # stream 1 MB at a time
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise HTTPException(status_code=413, detail="File exceeds the 1 GB limit")
            h.update(chunk)
            if len(head) < 6000:
                head += chunk[: 6000 - len(head)]
            tmp.write(chunk)
        tmp.flush()
        tmp.close()
        sha = h.hexdigest()
        text_sample = head.decode("utf-8", errors="ignore")
        combined = f"sha256={sha}\nfilename={file.filename}\n--snippet--\n{text_sample}"
        req = ScanRequest(target_type="file_text", target=combined, filename=file.filename, file_sha256=sha)
        return await _perform_scan(req, clam_path=tmp.name, org_id=ctx["org_id"])
    finally:
        try:
            tmp.close()
        except Exception:
            pass
        if os.path.exists(tmp.name):
            try:
                os.remove(tmp.name)
            except OSError:
                pass


@router.get("/scans", response_model=List[ScanResult])
async def list_scans(limit: int = 25, skip: int = 0, ctx=Depends(get_current_context)):
    docs = await db.scan_results.find({"org_id": ctx["org_id"]}, {"_id": 0}).sort("timestamp", -1).skip(skip).limit(limit).to_list(limit)
    return [ScanResult(**d) for d in docs]
