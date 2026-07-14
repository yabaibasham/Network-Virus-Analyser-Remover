"""Community Watch — GLOBAL (cross-org) consent-based neighbourhood threat sharing."""
from typing import List, Dict, Any

from fastapi import APIRouter, HTTPException, Depends

from database import db, now_iso
from models import CommunityAlert, CommunityAlertCreate
from events import _log_event
from context import get_current_context, ensure_write

router = APIRouter()

SEV_RANK = {"info": 0, "warning": 1, "danger": 2, "critical": 3}


@router.get("/community/alerts", response_model=List[CommunityAlert])
async def list_community_alerts(limit: int = 100, skip: int = 0, ctx=Depends(get_current_context)):
    docs = await db.community_alerts.find({}, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return [CommunityAlert(**d) for d in docs]


@router.post("/community/alerts", response_model=CommunityAlert)
async def create_community_alert(payload: CommunityAlertCreate, ctx=Depends(get_current_context)):
    ensure_write(ctx)
    data = {k: v for k, v in payload.model_dump().items() if v is not None}
    alert = CommunityAlert(**data, org_id=ctx["org_id"], org_name=ctx["org"].get("name"))
    await db.community_alerts.insert_one(alert.model_dump())
    await _log_event(alert.severity, "WATCH",
                     f"Community alert filed: {alert.title} ({alert.kind}) · {alert.region}",
                     org_id=ctx["org_id"])
    return alert


@router.post("/community/alerts/{alert_id}/corroborate")
async def corroborate_alert(alert_id: str, ctx=Depends(get_current_context)):
    doc = await db.community_alerts.find_one({"id": alert_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Alert not found")
    alert = CommunityAlert(**doc)
    alert.corroborations += 1
    if alert.corroborations >= 5 and alert.status == "active":
        alert.status = "verified"
    await db.community_alerts.replace_one({"id": alert_id}, alert.model_dump())
    return {"ok": True, "corroborations": alert.corroborations, "status": alert.status}


@router.get("/community/blocklist")
async def community_blocklist():
    docs = await db.community_alerts.find(
        {"status": {"$in": ["active", "verified"]}}, {"_id": 0}
    ).to_list(500)
    seen: Dict[str, Dict[str, Any]] = {}
    for d in docs:
        alert = CommunityAlert(**d)
        for ind in alert.indicators:
            key = ind.strip().lower()
            if not key:
                continue
            if key not in seen:
                seen[key] = {
                    "indicator": ind.strip(),
                    "kind": alert.kind,
                    "severity": alert.severity,
                    "confirmations": alert.corroborations,
                    "reports": 1,
                    "first_seen": alert.created_at,
                }
            else:
                e = seen[key]
                e["confirmations"] += alert.corroborations
                e["reports"] += 1
                if SEV_RANK[alert.severity] > SEV_RANK[e["severity"]]:
                    e["severity"] = alert.severity
                    e["kind"] = alert.kind
                if alert.created_at < e["first_seen"]:
                    e["first_seen"] = alert.created_at
    entries = sorted(seen.values(), key=lambda e: (e["confirmations"], e["reports"]), reverse=True)
    return {"count": len(entries), "entries": entries, "generated_at": now_iso()}
