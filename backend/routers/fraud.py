"""Fraud board — structured reports + authority-ready evidence packet."""
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter

from database import db, now_iso
from models import FraudReport, FraudReportCreate
from events import _log_event

router = APIRouter()


def _build_evidence_packet(rep: FraudReport) -> str:
    lines = [
        "SENTINELGRID — FRAUD EVIDENCE PACKET",
        f"Case reference : {rep.case_ref}",
        f"Generated (UTC): {rep.created_at}",
        f"Scheme type    : {rep.scheme_type.replace('_', ' ').title()}",
        "",
        "SUBJECT / PERPETRATOR",
        f"  Alias / handle : {rep.perpetrator_alias or 'unknown'}",
        f"  Jurisdictions  : {', '.join(rep.jurisdictions) or 'not specified'}",
        "",
        "IMPACT",
        f"  Estimated loss : {rep.amount_estimate or 'not quantified'}",
        f"  Victims known  : {rep.victims_count}",
        "",
        "CONTACT INDICATORS (phone / email / handle / URL / account)",
    ]
    lines += [f"  - {c}" for c in (rep.contact_indicators or ["none provided"])]
    lines += ["", "EVIDENCE LINKS"]
    lines += [f"  - {u}" for u in (rep.evidence_urls or ["none provided"])]
    lines += [
        "",
        "NARRATIVE",
        f"  {rep.narrative}",
        "",
        f"Reporter contact : {rep.reporter_contact or 'withheld'}",
        "",
        "SUGGESTED NEXT STEPS",
        "  1. Report to your national cybercrime unit:",
        "     - US:  FBI IC3 (ic3.gov) / FTC (reportfraud.ftc.gov)",
        "     - UK:  Action Fraud (actionfraud.police.uk) / 0300 123 2040",
        "     - AU:  ReportCyber (cyber.gov.au) / Scamwatch",
        "  2. Notify the impersonated bank/brand via their official fraud line.",
        "  3. Preserve original messages, headers and screenshots — do not alter.",
        "  4. Warn neighbours by publishing indicators to Community Watch.",
        "",
        "This packet is a citizen report to assist authorities. It is not a legal",
        "determination of guilt. SentinelGrid performs no covert surveillance.",
    ]
    return "\n".join(lines)


@router.get("/community/fraud-reports", response_model=List[FraudReport])
async def list_fraud_reports(limit: int = 50, skip: int = 0):
    docs = await db.fraud_reports.find({}, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return [FraudReport(**d) for d in docs]


@router.post("/community/fraud-reports", response_model=FraudReport)
async def create_fraud_report(payload: FraudReportCreate):
    seq = await db.fraud_reports.count_documents({}) + 1
    case_ref = f"SG-{datetime.now(timezone.utc).strftime('%Y%m')}-{seq:04d}"
    rep = FraudReport(case_ref=case_ref, **payload.model_dump())
    rep.evidence_packet = _build_evidence_packet(rep)
    await db.fraud_reports.insert_one(rep.model_dump())
    await _log_event("warning", "FRAUD",
                     f"Fraud report {case_ref} filed: {rep.scheme_type} · {rep.victims_count} victim(s).")
    return rep
