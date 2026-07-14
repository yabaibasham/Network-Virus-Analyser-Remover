"""Aggregate stats: public global (landing) + org-scoped (dashboard)."""
from fastapi import APIRouter, Depends

from database import db, now_iso, VT_API_KEY
from routers.community import community_blocklist
from routers.scanner import clamav_status
from context import get_current_context

router = APIRouter()


def _engines():
    return {
        "vt_enabled": bool(VT_API_KEY),
        "circl_enabled": True,
        "clamav_status": clamav_status(),
        "intel_engines": ["CIRCL hashlookup (govCERT-LU)", f"ClamAV ({clamav_status()})"]
        + (["VirusTotal"] if VT_API_KEY else []),
    }


async def _compute(match: dict):
    total = await db.devices.count_documents(match)
    infected = await db.devices.count_documents({**match, "status": "infected"})
    quarantined = await db.devices.count_documents({**match, "status": "quarantined"})
    scanning = await db.devices.count_documents({**match, "status": "scanning"})
    clean = await db.devices.count_documents({**match, "status": "clean"})
    missing = await db.devices.count_documents({**match, "missing_status": "missing"})
    scans = await db.scan_results.count_documents(match)
    threats = await db.threat_logs.count_documents({**match, "severity": {"$in": ["danger", "critical"]}})
    open_inc = await db.incidents.count_documents({**match, "status": {"$ne": "closed"}})
    fraud_reports = await db.fraud_reports.count_documents(match)
    remediations = await db.remediation_jobs.count_documents(match)
    # Community watch is global (cross-org)
    community_alerts = await db.community_alerts.count_documents({"status": {"$in": ["active", "verified"]}})
    bl = await community_blocklist()
    coverage = round((1 - (infected / total)) * 100, 1) if total else 100.0
    return {
        "devices_total": total, "devices_clean": clean, "devices_infected": infected,
        "devices_quarantined": quarantined, "devices_scanning": scanning, "devices_missing": missing,
        "scans_performed": scans, "threats_neutralized": threats, "open_incidents": open_inc,
        "community_alerts": community_alerts, "blocklist_size": bl["count"],
        "fraud_reports": fraud_reports, "remediations_run": remediations,
        "surface_coverage_pct": coverage, **_engines(),
    }


@router.get("/stats")
async def stats():
    # Public, global platform aggregate (used by the landing page)
    data = await _compute({})
    orgs = await db.orgs.count_documents({})
    data["orgs_total"] = orgs
    return data


@router.get("/org/stats")
async def org_stats(ctx=Depends(get_current_context)):
    # Org-scoped metrics for the authenticated console
    data = await _compute({"org_id": ctx["org_id"]})
    data["org_name"] = ctx["org"].get("name")
    data["role"] = ctx["role"]
    return data


@router.get("/")
async def root():
    return {"service": "SentinelGrid", "status": "operational", "time": now_iso(), **_engines()}
