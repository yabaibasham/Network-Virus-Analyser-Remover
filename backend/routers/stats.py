"""Aggregate stats + service root."""
from fastapi import APIRouter

from database import db, now_iso, VT_API_KEY
from routers.community import community_blocklist

router = APIRouter()


@router.get("/stats")
async def stats():
    total = await db.devices.count_documents({})
    infected = await db.devices.count_documents({"status": "infected"})
    quarantined = await db.devices.count_documents({"status": "quarantined"})
    scanning = await db.devices.count_documents({"status": "scanning"})
    clean = await db.devices.count_documents({"status": "clean"})
    missing = await db.devices.count_documents({"missing_status": "missing"})
    scans = await db.scan_results.count_documents({})
    threats = await db.threat_logs.count_documents({"severity": {"$in": ["danger", "critical"]}})
    open_inc = await db.incidents.count_documents({"status": {"$ne": "closed"}})
    community_alerts = await db.community_alerts.count_documents({"status": {"$in": ["active", "verified"]}})
    fraud_reports = await db.fraud_reports.count_documents({})
    remediations = await db.remediation_jobs.count_documents({})
    bl = await community_blocklist()
    coverage = round((1 - (infected / total)) * 100, 1) if total else 100.0
    return {
        "devices_total": total,
        "devices_clean": clean,
        "devices_infected": infected,
        "devices_quarantined": quarantined,
        "devices_scanning": scanning,
        "devices_missing": missing,
        "scans_performed": scans,
        "threats_neutralized": threats,
        "open_incidents": open_inc,
        "community_alerts": community_alerts,
        "blocklist_size": bl["count"],
        "fraud_reports": fraud_reports,
        "remediations_run": remediations,
        "surface_coverage_pct": coverage,
        "vt_enabled": bool(VT_API_KEY),
    }


@router.get("/")
async def root():
    return {"service": "SentinelGrid", "status": "operational", "time": now_iso(), "vt_enabled": bool(VT_API_KEY)}
