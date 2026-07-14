"""Seed data and idempotent startup seeding."""
from database import db, log, now_iso
from models import Device, ThreatLog, CommunityAlert, Membership

DEMO_ORG_ID = "org_demo"
DEMO_OWNER_ID = "user_testauditor01"

SEED_DEVICES = [
    {"hostname": "core-linux-01", "device_type": "linux_server", "os": "Ubuntu 24.04 LTS",
     "ip_address": "10.0.4.21", "location": "Frankfurt DC-1", "memory_load": 64.2, "cpu_load": 42.1,
     "owner_email": "ops@acme.io"},
    {"hostname": "tesla-models-x7", "device_type": "tesla_vehicle", "os": "Tesla OS 2026.4.1",
     "ip_address": "10.0.9.71", "location": "Mobile / Vienna", "memory_load": 38.5, "cpu_load": 22.4,
     "owner_email": "fleet@acme.io"},
    {"hostname": "macbook-ada", "device_type": "macbook", "os": "macOS 15.3 Sequoia",
     "ip_address": "10.0.2.14", "location": "Berlin Office", "memory_load": 71.0, "cpu_load": 51.0,
     "owner_email": "ada.l@acme.io"},
    {"hostname": "winws-finance", "device_type": "windows_pc", "os": "Windows 11 Pro 24H2",
     "ip_address": "10.0.2.55", "location": "Berlin Office", "memory_load": 82.3, "cpu_load": 67.8,
     "owner_email": "finance@acme.io"},
    {"hostname": "ipcam-lobby-04", "device_type": "ip_camera", "os": "Hikvision FW 5.6.0",
     "ip_address": "10.0.7.104", "location": "HQ Lobby", "memory_load": 28.1, "cpu_load": 14.6,
     "owner_email": "facilities@acme.io"},
    {"hostname": "rpi-edge-09", "device_type": "raspberry_pi", "os": "Raspberry Pi OS Bookworm",
     "ip_address": "10.0.5.9", "location": "Warehouse 3", "memory_load": 19.4, "cpu_load": 8.2},
    {"hostname": "phone-ceo-iphone", "device_type": "iphone", "os": "iOS 18.3",
     "ip_address": "10.0.3.7", "location": "Mobile / London", "memory_load": 44.0, "cpu_load": 18.0,
     "owner_email": "ceo@acme.io"},
    {"hostname": "android-field-22", "device_type": "android", "os": "Android 15 (One UI 7)",
     "ip_address": "10.0.3.22", "location": "Mobile / Lagos", "memory_load": 58.2, "cpu_load": 31.5,
     "owner_email": "field@acme.io"},
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

SEED_ALERTS = [
    {"kind": "phishing", "title": "Fake parcel redelivery SMS circulating",
     "description": "Residents report a texted link claiming a missed delivery. The page harvests card details and a one-time passcode.",
     "indicators": ["https://royal-parcel-redeliver.top/track", "+44 7700 900123"],
     "severity": "danger", "region": "North District", "reporter_handle": "watch_captain_07",
     "corroborations": 12, "status": "verified"},
    {"kind": "bank_drop", "title": "Crew recruiting 'money mules' at the community centre",
     "description": "A group is offering fast cash to let strangers move money through personal accounts. This is money-laundering; participants can face charges.",
     "indicators": ["@quickcash_relief", "sortcode 04-00-04"],
     "severity": "critical", "region": "Central", "reporter_handle": "neighbour",
     "corroborations": 5, "status": "active"},
    {"kind": "identity_theft", "title": "Utility 'account update' emails spoofing the local provider",
     "description": "Emails ask you to 'reconfirm' your name, DOB and address to avoid disconnection. The provider never asks for this by email.",
     "indicators": ["billing@power-account-update.click", "https://power-account-update.click/verify"],
     "severity": "danger", "region": "Local Area", "reporter_handle": "watch_admin",
     "corroborations": 9, "status": "verified"},
    {"kind": "keylogger", "title": "Free 'PC speed booster' bundling a credential stealer",
     "description": "A download advertised on a local forum installs a keylogger. Uninstall via SentinelGrid and rotate any passwords typed after install.",
     "indicators": ["turbo-pc-booster-free.xyz", "sha256:not-indexed"],
     "severity": "danger", "region": "Local Area", "reporter_handle": "sentinel_analyst",
     "corroborations": 7, "status": "active"},
    {"kind": "spoofed_caller", "title": "Callers impersonating the fraud team of a major bank",
     "description": "Caller ID shows the real bank number (spoofed). They pressure you to move funds to a 'safe account'. Hang up and call the number on your card.",
     "indicators": ["+1 202-555-0114"],
     "severity": "warning", "region": "Everywhere", "reporter_handle": "neighbour",
     "corroborations": 3, "status": "active"},
]


async def ensure_seed():
    # Demo organisation + owner (also powers the seeded test session)
    if not await db.orgs.find_one({"org_id": DEMO_ORG_ID}):
        await db.orgs.insert_one({
            "org_id": DEMO_ORG_ID, "name": "SentinelGrid Demo", "org_type": "business",
            "region": "Global", "owner_user_id": DEMO_OWNER_ID, "plan": "demo",
            "created_at": now_iso(),
        })
    if not await db.users.find_one({"user_id": DEMO_OWNER_ID}):
        await db.users.insert_one({
            "user_id": DEMO_OWNER_ID, "email": "auditor@sentinelgrid.local",
            "name": "Demo Owner", "picture": "", "created_at": now_iso(),
            "active_org_id": DEMO_ORG_ID,
        })
    if not await db.memberships.find_one({"org_id": DEMO_ORG_ID, "user_id": DEMO_OWNER_ID}):
        await db.memberships.insert_one(
            Membership(org_id=DEMO_ORG_ID, user_id=DEMO_OWNER_ID, role="owner").model_dump()
        )
    # Ensure the demo owner points at the demo org (covers pre-existing user docs)
    await db.users.update_one(
        {"user_id": DEMO_OWNER_ID, "active_org_id": None}, {"$set": {"active_org_id": DEMO_ORG_ID}}
    )

    if await db.devices.count_documents({}) == 0:
        log.info("Seeding devices …")
        for d in SEED_DEVICES:
            dev = Device(**{**d, "org_id": DEMO_ORG_ID})
            await db.devices.insert_one(dev.model_dump())
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
            tl = ThreatLog(**{**entry, "org_id": DEMO_ORG_ID})
            await db.threat_logs.insert_one(tl.model_dump())
    if await db.community_alerts.count_documents({}) == 0:
        for entry in SEED_ALERTS:
            # Community alerts are GLOBAL (cross-org) by design; provenance = demo org
            ca = CommunityAlert(**{**entry, "org_id": DEMO_ORG_ID, "org_name": "SentinelGrid Demo"})
            await db.community_alerts.insert_one(ca.model_dump())

    # Migrate any pre-tenancy records into the demo org (community alerts stay global)
    for coll in ["devices", "threat_logs", "incidents", "scan_results",
                 "remediation_jobs", "fraud_reports"]:
        await db[coll].update_many({"org_id": {"$exists": False}}, {"$set": {"org_id": DEMO_ORG_ID}})
        await db[coll].update_many({"org_id": None}, {"$set": {"org_id": DEMO_ORG_ID}})
