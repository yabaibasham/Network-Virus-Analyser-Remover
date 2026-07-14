"""Device fleet: listing, surface inspection, actions, and asset recovery."""
import random
from typing import List

from fastapi import APIRouter, HTTPException, Depends

from database import db, now_iso
from models import Device, DeviceCreate, DeviceAction, ReportMissingPayload, GeoPoint
from events import _log_event
from context import get_current_context, ensure_write

router = APIRouter()


@router.get("/devices", response_model=List[Device])
async def list_devices(ctx=Depends(get_current_context)):
    docs = await db.devices.find({"org_id": ctx["org_id"]}, {"_id": 0}).to_list(500)
    return [Device(**d) for d in docs]


@router.get("/devices/{device_id}", response_model=Device)
async def get_device(device_id: str, ctx=Depends(get_current_context)):
    doc = await db.devices.find_one({"id": device_id, "org_id": ctx["org_id"]}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Device not found")
    return Device(**doc)


@router.post("/devices", response_model=Device)
async def create_device(payload: DeviceCreate, ctx=Depends(get_current_context)):
    ensure_write(ctx)
    dev = Device(**payload.model_dump(), org_id=ctx["org_id"])
    await db.devices.insert_one(dev.model_dump())
    await _log_event("info", "FLEET", f"Device {dev.hostname} ({dev.device_type}) registered.", dev)
    return dev


@router.get("/devices/{device_id}/surface")
async def get_device_surface(device_id: str, ctx=Depends(get_current_context)):
    doc = await db.devices.find_one({"id": device_id, "org_id": ctx["org_id"]}, {"_id": 0})
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
        {"proto": "udp", "remote": "1.1.1.1:53", "state": "—"},
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


@router.post("/devices/{device_id}/action")
async def device_action(device_id: str, payload: DeviceAction, ctx=Depends(get_current_context)):
    ensure_write(ctx)
    doc = await db.devices.find_one({"id": device_id, "org_id": ctx["org_id"]}, {"_id": 0})
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
    dev.status = new_status  # type: ignore[assignment]
    await _log_event(sev, payload.action.upper(), msg, dev)
    return {"ok": True, "status": new_status, "message": msg}


# --- Recovery (legitimate, owner-consented lost/stolen device tracking) ---
@router.post("/devices/{device_id}/report-missing")
async def report_missing(device_id: str, payload: ReportMissingPayload, ctx=Depends(get_current_context)):
    ensure_write(ctx)
    doc = await db.devices.find_one({"id": device_id, "org_id": ctx["org_id"]}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Device not found")
    dev = Device(**doc)

    geo = None
    if payload.last_lat is not None and payload.last_lon is not None:
        geo = GeoPoint(lat=payload.last_lat, lon=payload.last_lon,
                       accuracy_m=payload.accuracy_m, source="owner_agent")
    elif dev.last_known_location is None:
        rng = random.Random(dev.fingerprint)
        geo = GeoPoint(
            lat=round(40 + rng.uniform(-15, 15), 5),
            lon=round(10 + rng.uniform(-25, 25), 5),
            accuracy_m=payload.accuracy_m,
            source="last_wifi",
        )

    update = {"missing_status": "missing"}
    if geo:
        update["last_known_location"] = geo.model_dump()
    await db.devices.update_one({"id": device_id}, {"$set": update})

    msg = f"{dev.hostname} reported MISSING by owner."
    if payload.note:
        msg += f" Note: {payload.note}"
    dev.missing_status = "missing"
    await _log_event("danger", "RECOVERY", msg, dev)
    return {"ok": True, "missing_status": "missing", "last_known_location": (geo.model_dump() if geo else None)}


@router.post("/devices/{device_id}/mark-recovered")
async def mark_recovered(device_id: str, ctx=Depends(get_current_context)):
    ensure_write(ctx)
    doc = await db.devices.find_one({"id": device_id, "org_id": ctx["org_id"]}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Device not found")
    dev = Device(**doc)
    await db.devices.update_one(
        {"id": device_id},
        {"$set": {"missing_status": "recovered"}},
    )
    dev.missing_status = "recovered"
    await _log_event("info", "RECOVERY", f"{dev.hostname} marked RECOVERED.", dev)
    return {"ok": True, "missing_status": "recovered"}


@router.get("/recovery")
async def recovery_list(ctx=Depends(get_current_context)):
    docs = await db.devices.find(
        {"org_id": ctx["org_id"], "missing_status": {"$in": ["missing", "recovered"]}}, {"_id": 0}
    ).to_list(200)
    return [Device(**d).model_dump() for d in docs]
