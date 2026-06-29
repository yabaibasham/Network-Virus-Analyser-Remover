"""
SentinelGrid Backend
Universal device threat-intelligence dashboard with AI heuristic scan.
"""
import os
import re
import json
import uuid
import random
import logging
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional, Literal

from fastapi import FastAPI, APIRouter, HTTPException, UploadFile, File, Form
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, ConfigDict

from emergentintegrations.llm.chat import LlmChat, UserMessage


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

EMERGENT_LLM_KEY = os.environ.get("EMERGENT_LLM_KEY")

app = FastAPI(title="SentinelGrid API")
api_router = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("sentinelgrid")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
DeviceType = Literal[
    "linux_server", "windows_pc", "macbook", "android", "iphone",
    "ip_camera", "tesla_vehicle", "iot_sensor", "router", "raspberry_pi"
]
DeviceStatus = Literal["clean", "scanning", "infected", "quarantined", "offline"]


class Device(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str
    device_type: DeviceType
    os: str
    ip_address: str
    location: str
    status: DeviceStatus = "clean"
    memory_load: float = 0.0
    cpu_load: float = 0.0
    last_seen: str = Field(default_factory=now_iso)
    threats_detected: int = 0
    fingerprint: str = Field(default_factory=lambda: hashlib.sha1(os.urandom(8)).hexdigest()[:16])


class DeviceCreate(BaseModel):
    hostname: str
    device_type: DeviceType
    os: str
    ip_address: str
    location: str


class ThreatLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=now_iso)
    severity: Literal["info", "warning", "danger", "critical"]
    device_id: Optional[str] = None
    device_hostname: Optional[str] = None
    category: str  # e.g. RAT, Trojan, Rootkit, Keylogger, URL, File
    message: str


class ScanRequest(BaseModel):
    target_type: Literal["url", "file_hash", "file_text"]
    target: str
    filename: Optional[str] = None


class ScanResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=now_iso)
    target_type: str
    target: str
    filename: Optional[str] = None
    verdict: Literal["clean", "suspicious", "malicious"]
    risk_score: int  # 0-100
    iocs: List[str]
    categories: List[str]
    ai_reasoning: str
    recommended_actions: List[str]


class DeviceAction(BaseModel):
    action: Literal["quarantine", "safe_remove", "rescan", "release"]


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------
SEED_DEVICES = [
    {"hostname": "core-linux-01", "device_type": "linux_server", "os": "Ubuntu 24.04 LTS",
     "ip_address": "10.0.4.21", "location": "Frankfurt DC-1", "memory_load": 64.2, "cpu_load": 42.1},
    {"hostname": "tesla-models-x7", "device_type": "tesla_vehicle", "os": "Tesla OS 2026.4.1",
     "ip_address": "10.0.9.71", "location": "Mobile / Vienna", "memory_load": 38.5, "cpu_load": 22.4},
    {"hostname": "macbook-ada", "device_type": "macbook", "os": "macOS 15.3 Sequoia",
     "ip_address": "10.0.2.14", "location": "Berlin Office", "memory_load": 71.0, "cpu_load": 51.0},
    {"hostname": "winws-finance", "device_type": "windows_pc", "os": "Windows 11 Pro 24H2",
     "ip_address": "10.0.2.55", "location": "Berlin Office", "memory_load": 82.3, "cpu_load": 67.8},
    {"hostname": "ipcam-lobby-04", "device_type": "ip_camera", "os": "Hikvision FW 5.6.0",
     "ip_address": "10.0.7.104", "location": "HQ Lobby", "memory_load": 28.1, "cpu_load": 14.6},
    {"hostname": "rpi-edge-09", "device_type": "raspberry_pi", "os": "Raspberry Pi OS Bookworm",
     "ip_address": "10.0.5.9", "location": "Warehouse 3", "memory_load": 19.4, "cpu_load": 8.2},
    {"hostname": "phone-ceo-iphone", "device_type": "iphone", "os": "iOS 18.3",
     "ip_address": "10.0.3.7", "location": "Mobile / London", "memory_load": 44.0, "cpu_load": 18.0},
    {"hostname": "android-field-22", "device_type": "android", "os": "Android 15 (One UI 7)",
     "ip_address": "10.0.3.22", "location": "Mobile / Lagos", "memory_load": 58.2, "cpu_load": 31.5},
    {"hostname": "edge-router-gw", "device_type": "router", "os": "OpenWrt 23.05",
     "ip_address": "10.0.0.1", "location": "Frankfurt DC-1", "memory_load": 22.0, "cpu_load": 11.3},
    {"hostname": "iot-thermo-12", "device_type": "iot_sensor", "os": "Zephyr RTOS 3.6",
     "ip_address": "10.0.6.12", "location": "HQ HVAC Closet", "memory_load": 9.8, "cpu_load": 4.1},
]

SEED_LOGS = [
    {"severity": "info", "category": "SYS", "message": "Baseline sweep completed across 10 endpoints."},
    {"severity": "warning", "category": "BEHAVIOR", "message": "Anomalous outbound TCP/4444 burst from winws-finance."},
    {"severity": "danger", "category": "RAT", "message": "njRAT signature surface match on winws-finance (proc: svhost.exe)."},
    {"severity": "info", "category": "FIRMWARE", "message": "tesla-models-x7 firmware integrity attested."},
    {"severity": "critical", "category": "ROOTKIT", "message": "Kernel hook anomaly on ipcam-lobby-04 — handler 0xFFFF82A1."},
    {"severity": "warning", "category": "MEMORY", "message": "macbook-ada memory pressure 71% — scan rescheduled."},
]


async def ensure_seed():
    if await db.devices.count_documents({}) == 0:
        log.info("Seeding devices …")
        for d in SEED_DEVICES:
            dev = Device(**d)
            await db.devices.insert_one(dev.model_dump())
        # Tag one as infected so the UI has signal
        await db.devices.update_one(
            {"hostname": "winws-finance"},
            {"$set": {"status": "infected", "threats_detected": 3}},
        )
        await db.devices.update_one(
            {"hostname": "ipcam-lobby-04"},
            {"$set": {"status": "infected", "threats_detected": 1}},
        )
    if await db.threat_logs.count_documents({}) == 0:
        for entry in SEED_LOGS:
            tl = ThreatLog(**entry)
            await db.threat_logs.insert_one(tl.model_dump())


@app.on_event("startup")
async def on_startup():
    await ensure_seed()


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------
@api_router.get("/devices", response_model=List[Device])
async def list_devices():
    docs = await db.devices.find({}, {"_id": 0}).to_list(500)
    return [Device(**d) for d in docs]


@api_router.get("/devices/{device_id}", response_model=Device)
async def get_device(device_id: str):
    doc = await db.devices.find_one({"id": device_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Device not found")
    return Device(**doc)


@api_router.post("/devices", response_model=Device)
async def create_device(payload: DeviceCreate):
    dev = Device(**payload.model_dump())
    await db.devices.insert_one(dev.model_dump())
    await _log_event("info", "FLEET", f"Device {dev.hostname} ({dev.device_type}) registered.", dev)
    return dev


@api_router.get("/devices/{device_id}/surface")
async def get_device_surface(device_id: str):
    """Synthetic deep-surface payload: processes, memory map, network, RAT checks."""
    doc = await db.devices.find_one({"id": device_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Device not found")
    dev = Device(**doc)
    rng = random.Random(dev.fingerprint)

    proc_pool = [
        ("systemd", "/usr/lib/systemd/systemd", "running"),
        ("kworker/u8:2", "[kernel]", "running"),
        ("sshd", "/usr/sbin/sshd -D", "listening"),
        ("nginx", "/usr/sbin/nginx -g daemon on;", "listening"),
        ("svhost.exe", "C:\\Users\\Public\\svhost.exe -k netsvcs", "suspicious"),
        ("teslad", "/opt/tesla/bin/teslad --otap", "running"),
        ("hik-stream", "/opt/hik/bin/hik-stream --rtsp", "running"),
        ("python3", "/usr/bin/python3 /opt/miner/x.py", "suspicious"),
        ("WindowServer", "/System/Library/...", "running"),
        ("crond", "/usr/sbin/crond -n", "running"),
    ]
    n_proc = rng.randint(6, 9)
    processes = [
        {
            "pid": rng.randint(100, 65000),
            "name": p[0], "path": p[1], "state": p[2],
            "cpu": round(rng.uniform(0.0, 38.0), 1),
            "mem": round(rng.uniform(0.1, 22.0), 1),
        }
        for p in rng.sample(proc_pool, n_proc)
    ]

    memory_blocks = []
    for i in range(64):
        kind = rng.choices(
            ["used", "free", "cache", "kernel", "suspicious"],
            weights=[40, 30, 20, 9, 1 if dev.status == "infected" else 0.1],
        )[0]
        memory_blocks.append({"id": i, "kind": kind, "size_kb": rng.randint(128, 8192)})

    rat_checks = [
        {"check": "Kernel hook integrity", "status": "fail" if dev.status == "infected" and rng.random() > 0.5 else "pass"},
        {"check": "Hidden process scan", "status": "fail" if dev.status == "infected" else "pass"},
        {"check": "C2 beacon heuristic (DNS, TLS-SNI)", "status": "warn" if dev.status == "infected" else "pass"},
        {"check": "Persistence (cron / launchd / registry)", "status": "pass"},
        {"check": "Firmware attestation", "status": "pass" if dev.device_type != "ip_camera" else "warn"},
        {"check": "Memory page W^X compliance", "status": "pass"},
        {"check": "RAT signature surface (njRAT, DarkComet, Quasar, AsyncRAT, NetWire)", "status": "fail" if dev.status == "infected" else "pass"},
    ]

    network = [
        {"proto": "tcp", "remote": f"10.0.{rng.randint(0,9)}.{rng.randint(1,250)}:{rng.choice([22,80,443,8080])}", "state": "ESTAB"},
        {"proto": "tcp", "remote": f"185.220.{rng.randint(0,255)}.{rng.randint(1,250)}:4444", "state": "ESTAB"} if dev.status == "infected" else None,
        {"proto": "udp", "remote": f"1.1.1.1:53", "state": "—"},
        {"proto": "tcp", "remote": f"api.{['github','cloudflare','tesla'][rng.randint(0,2)]}.com:443", "state": "ESTAB"},
    ]
    network = [n for n in network if n]

    return {
        "device": dev.model_dump(),
        "processes": processes,
        "memory_blocks": memory_blocks,
        "rat_checks": rat_checks,
        "network": network,
        "generated_at": now_iso(),
    }


@api_router.post("/devices/{device_id}/action")
async def device_action(device_id: str, payload: DeviceAction):
    doc = await db.devices.find_one({"id": device_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Device not found")
    dev = Device(**doc)

    new_status = dev.status
    msg = ""
    sev = "info"
    if payload.action == "quarantine":
        new_status = "quarantined"
        msg = f"{dev.hostname} isolated from network. All sessions terminated."
        sev = "warning"
    elif payload.action == "safe_remove":
        new_status = "clean"
        msg = f"Threats safely removed from {dev.hostname}. Surface re-attested."
        sev = "info"
        await db.devices.update_one({"id": device_id}, {"$set": {"threats_detected": 0}})
    elif payload.action == "rescan":
        new_status = "scanning"
        msg = f"Deep memory + filesystem sweep initiated on {dev.hostname}."
        sev = "info"
    elif payload.action == "release":
        new_status = "clean"
        msg = f"{dev.hostname} released from quarantine."
        sev = "info"

    await db.devices.update_one(
        {"id": device_id},
        {"$set": {"status": new_status, "last_seen": now_iso()}},
    )
    await _log_event(sev, payload.action.upper(), msg, dev)
    return {"ok": True, "status": new_status, "message": msg}


# ---------------------------------------------------------------------------
# Threat logs
# ---------------------------------------------------------------------------
async def _log_event(severity: str, category: str, message: str, device: Optional[Device] = None):
    entry = ThreatLog(
        severity=severity, category=category, message=message,
        device_id=device.id if device else None,
        device_hostname=device.hostname if device else None,
    )
    await db.threat_logs.insert_one(entry.model_dump())
    return entry


@api_router.get("/threat-logs", response_model=List[ThreatLog])
async def list_threat_logs(limit: int = 50):
    cursor = db.threat_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
    docs = await cursor.to_list(limit)
    return [ThreatLog(**d) for d in docs]


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------
@api_router.get("/stats")
async def stats():
    total = await db.devices.count_documents({})
    infected = await db.devices.count_documents({"status": "infected"})
    quarantined = await db.devices.count_documents({"status": "quarantined"})
    scanning = await db.devices.count_documents({"status": "scanning"})
    clean = await db.devices.count_documents({"status": "clean"})
    scans = await db.scan_results.count_documents({})
    threats = await db.threat_logs.count_documents({"severity": {"$in": ["danger", "critical"]}})
    coverage = round((1 - (infected / total)) * 100, 1) if total else 100.0
    return {
        "devices_total": total,
        "devices_clean": clean,
        "devices_infected": infected,
        "devices_quarantined": quarantined,
        "devices_scanning": scanning,
        "scans_performed": scans,
        "threats_neutralized": threats,
        "surface_coverage_pct": coverage,
    }


# ---------------------------------------------------------------------------
# Scanner (AI heuristic via Claude Sonnet 4.6 + local IOC matching)
# ---------------------------------------------------------------------------
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
        if "@" in t or "//" in t.split("://", 1)[-1][:120].split("/", 1)[0]:
            if "@" in t.split("://", 1)[-1].split("/", 1)[0]:
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
    """Call Claude Sonnet 4.6 to provide structured reasoning & final verdict."""
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
        # Extract JSON
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


def _verdict_from_score(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score >= 35:
        return "suspicious"
    return "clean"


@api_router.post("/scan", response_model=ScanResult)
async def run_scan(req: ScanRequest):
    local = _local_ioc_scan(req.target_type, req.target)
    ai = await _ai_heuristic(req.target_type, req.target, local)
    final_score = max(0, min(100, local["score"] + ai["verdict_score_adjust"]))
    verdict = _verdict_from_score(final_score)

    result = ScanResult(
        target_type=req.target_type,
        target=req.target,
        filename=req.filename,
        verdict=verdict,
        risk_score=final_score,
        iocs=local["iocs"] or ["No static IOCs matched"],
        categories=local["categories"],
        ai_reasoning=ai["reasoning"],
        recommended_actions=ai["recommended_actions"],
    )
    await db.scan_results.insert_one(result.model_dump())

    sev = {"malicious": "critical", "suspicious": "warning", "clean": "info"}[verdict]
    label = req.filename or req.target
    await _log_event(sev, "SCAN", f"{verdict.upper()} • score {final_score}/100 • {label[:80]}")
    return result


@api_router.post("/scan/upload", response_model=ScanResult)
async def scan_upload(file: UploadFile = File(...)):
    raw = await file.read()
    sha = hashlib.sha256(raw).hexdigest()
    # Sample first 6kb as text for heuristic
    try:
        text_sample = raw[:6000].decode("utf-8", errors="ignore")
    except Exception:
        text_sample = ""
    combined = f"sha256={sha}\nfilename={file.filename}\n--snippet--\n{text_sample}"
    return await run_scan(ScanRequest(target_type="file_text", target=combined, filename=file.filename))


@api_router.get("/scans", response_model=List[ScanResult])
async def list_scans(limit: int = 25):
    docs = await db.scan_results.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit).to_list(limit)
    return [ScanResult(**d) for d in docs]


@api_router.get("/")
async def root():
    return {"service": "SentinelGrid", "status": "operational", "time": now_iso()}


# ---------------------------------------------------------------------------
# Wire up
# ---------------------------------------------------------------------------
app.include_router(api_router)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
