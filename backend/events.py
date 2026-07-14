"""Threat-log emission and automatic incident correlation."""
from typing import Optional, Dict, Any

from database import db, now_iso
from models import ThreatLog, Incident, Device


async def _log_event(severity: str, category: str, message: str,
                     device: Optional[Device] = None, org_id: Optional[str] = None):
    org = org_id or (device.org_id if device else None)
    entry = ThreatLog(
        severity=severity, category=category, message=message,
        device_id=device.id if device else None,
        device_hostname=device.hostname if device else None,
        org_id=org,
    )
    await db.threat_logs.insert_one(entry.model_dump())
    # Auto-correlate into incident for warning+
    if severity in ("warning", "danger", "critical"):
        await _correlate_incident(entry, device)
    return entry


async def _correlate_incident(entry: ThreatLog, device: Optional[Device]):
    """Group recent severity events from the same device/category into an open incident."""
    query: Dict[str, Any] = {"status": {"$ne": "closed"}, "category": entry.category,
                             "org_id": entry.org_id}
    if device:
        query["device_id"] = device.id
    existing = await db.incidents.find_one(query, {"_id": 0})
    if existing:
        inc = Incident(**existing)
        inc.log_ids.append(entry.id)
        inc.updated_at = now_iso()
        sev_rank = {"info": 0, "warning": 1, "danger": 2, "critical": 3}
        if sev_rank[entry.severity] > sev_rank[inc.severity]:
            inc.severity = entry.severity  # type: ignore[assignment]
        inc.timeline.append({"at": entry.timestamp, "event": entry.message, "severity": entry.severity})
        await db.incidents.replace_one({"id": inc.id}, inc.model_dump())
        await db.threat_logs.update_one({"id": entry.id}, {"$set": {"incident_id": inc.id}})
    else:
        title = f"{entry.category} on {device.hostname}" if device else f"{entry.category} event"
        inc = Incident(
            title=title,
            severity=entry.severity,  # type: ignore[arg-type]
            category=entry.category,
            summary=entry.message,
            device_id=device.id if device else None,
            device_hostname=device.hostname if device else None,
            log_ids=[entry.id],
            timeline=[{"at": entry.timestamp, "event": entry.message, "severity": entry.severity}],
            org_id=entry.org_id,
        )
        await db.incidents.insert_one(inc.model_dump())
        await db.threat_logs.update_one({"id": entry.id}, {"$set": {"incident_id": inc.id}})
