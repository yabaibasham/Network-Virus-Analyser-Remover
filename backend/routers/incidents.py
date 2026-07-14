"""Threat logs and correlated incident queue (org-scoped)."""
from typing import List, Dict

from fastapi import APIRouter, HTTPException, Depends

from database import db, now_iso
from models import ThreatLog, Incident
from context import get_current_context, ensure_write

router = APIRouter()


@router.get("/threat-logs", response_model=List[ThreatLog])
async def list_threat_logs(limit: int = 50, skip: int = 0, ctx=Depends(get_current_context)):
    cursor = db.threat_logs.find({"org_id": ctx["org_id"]}, {"_id": 0}).sort("timestamp", -1).skip(skip).limit(limit)
    docs = await cursor.to_list(limit)
    return [ThreatLog(**d) for d in docs]


@router.get("/incidents", response_model=List[Incident])
async def list_incidents(limit: int = 50, skip: int = 0, ctx=Depends(get_current_context)):
    docs = await db.incidents.find({"org_id": ctx["org_id"]}, {"_id": 0}).sort("updated_at", -1).skip(skip).limit(limit).to_list(limit)
    return [Incident(**d) for d in docs]


@router.post("/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, payload: Dict[str, str], ctx=Depends(get_current_context)):
    ensure_write(ctx)
    status = payload.get("status")
    if status not in ("open", "triaged", "contained", "closed"):
        raise HTTPException(400, "invalid status")
    doc = await db.incidents.find_one({"id": incident_id, "org_id": ctx["org_id"]}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Incident not found")
    inc = Incident(**doc)
    inc.status = status  # type: ignore[assignment]
    inc.updated_at = now_iso()
    inc.timeline.append({"at": inc.updated_at, "event": f"status → {status}", "severity": "info"})
    await db.incidents.replace_one({"id": incident_id}, inc.model_dump())
    return {"ok": True, "status": status}
