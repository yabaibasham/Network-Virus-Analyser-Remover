"""Heuristic scanner: static IOC pass + AI triage + optional VirusTotal."""
import re
import json
import uuid
import base64
import hashlib
from typing import List, Optional, Dict, Any

import httpx
from fastapi import APIRouter, UploadFile, File

from emergentintegrations.llm.chat import LlmChat, UserMessage

from database import db, now_iso, log, EMERGENT_LLM_KEY, VT_API_KEY
from models import ScanRequest, ScanResult
from events import _log_event

router = APIRouter()

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


@router.post("/scan", response_model=ScanResult)
async def run_scan(req: ScanRequest):
    local = _local_ioc_scan(req.target_type, req.target)
    ai = await _ai_heuristic(req.target_type, req.target, local)
    vt = await _virustotal_lookup(req.target_type, req.target)

    score = local["score"] + ai["verdict_score_adjust"]
    if vt and vt.get("engines_malicious"):
        score += min(30, int(vt["engines_malicious"]) * 5)
    final_score = max(0, min(100, score))
    verdict = _verdict_from_score(final_score)

    result = ScanResult(
        target_type=req.target_type,
        target=req.target,
        filename=req.filename,
        verdict=verdict,  # type: ignore[arg-type]
        risk_score=final_score,
        iocs=local["iocs"] or ["No static IOCs matched"],
        categories=local["categories"],
        ai_reasoning=ai["reasoning"],
        recommended_actions=ai["recommended_actions"],
        vt_summary=vt,
    )
    await db.scan_results.insert_one(result.model_dump())

    sev = {"malicious": "critical", "suspicious": "warning", "clean": "info"}[verdict]
    label = req.filename or req.target
    await _log_event(sev, "SCAN", f"{verdict.upper()} · score {final_score}/100 · {label[:80]}")
    return result


@router.post("/scan/upload", response_model=ScanResult)
async def scan_upload(file: UploadFile = File(...)):
    raw = await file.read()
    sha = hashlib.sha256(raw).hexdigest()
    try:
        text_sample = raw[:6000].decode("utf-8", errors="ignore")
    except Exception:
        text_sample = ""
    combined = f"sha256={sha}\nfilename={file.filename}\n--snippet--\n{text_sample}"
    return await run_scan(ScanRequest(target_type="file_text", target=combined, filename=file.filename))


@router.get("/scans", response_model=List[ScanResult])
async def list_scans(limit: int = 25, skip: int = 0):
    docs = await db.scan_results.find({}, {"_id": 0}).sort("timestamp", -1).skip(skip).limit(limit).to_list(limit)
    return [ScanResult(**d) for d in docs]
