"""Pydantic models and shared literals for SentinelGrid."""
import os
import uuid
import hashlib
from typing import List, Optional, Literal, Dict, Any

from pydantic import BaseModel, Field, ConfigDict

from database import now_iso

DeviceType = Literal[
    "linux_server", "windows_pc", "macbook", "android", "iphone",
    "ip_camera", "tesla_vehicle", "iot_sensor", "router", "raspberry_pi"
]
DeviceStatus = Literal["clean", "scanning", "infected", "quarantined", "offline"]
MissingStatus = Literal["active", "missing", "recovered"]


class GeoPoint(BaseModel):
    lat: float
    lon: float
    accuracy_m: int = 50
    reported_at: str = Field(default_factory=now_iso)
    source: str = "owner_agent"  # owner_agent, last_wifi, last_cell, manual


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
    owner_email: Optional[str] = None
    missing_status: MissingStatus = "active"
    last_known_location: Optional[GeoPoint] = None


class DeviceCreate(BaseModel):
    hostname: str
    device_type: DeviceType
    os: str
    ip_address: str
    location: str
    owner_email: Optional[str] = None


class ThreatLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=now_iso)
    severity: Literal["info", "warning", "danger", "critical"]
    device_id: Optional[str] = None
    device_hostname: Optional[str] = None
    category: str
    message: str
    incident_id: Optional[str] = None


class Incident(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)
    title: str
    severity: Literal["info", "warning", "danger", "critical"]
    status: Literal["open", "triaged", "contained", "closed"] = "open"
    device_id: Optional[str] = None
    device_hostname: Optional[str] = None
    category: str
    summary: str
    log_ids: List[str] = []
    timeline: List[Dict[str, Any]] = []


class ScanRequest(BaseModel):
    target_type: Literal["url", "file_hash", "file_text"]
    target: str
    filename: Optional[str] = None
    file_sha256: Optional[str] = None  # set by upload path for hash-intel lookups


class ScanResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=now_iso)
    target_type: str
    target: str
    filename: Optional[str] = None
    verdict: Literal["clean", "suspicious", "malicious"]
    risk_score: int
    iocs: List[str]
    categories: List[str]
    ai_reasoning: str
    recommended_actions: List[str]
    vt_summary: Optional[Dict[str, Any]] = None       # virustotal block if available
    circl_summary: Optional[Dict[str, Any]] = None    # CIRCL hashlookup (govCERT-LU)
    clamav_summary: Optional[Dict[str, Any]] = None   # local ClamAV signature scan


class DeviceAction(BaseModel):
    action: Literal["quarantine", "safe_remove", "rescan", "release"]


class ReportMissingPayload(BaseModel):
    last_lat: Optional[float] = None
    last_lon: Optional[float] = None
    accuracy_m: int = 100
    note: Optional[str] = None


AlertKind = Literal[
    "scam", "phishing", "malware_url", "keylogger", "bank_drop",
    "identity_theft", "ransomware", "spoofed_caller", "other"
]


class CommunityAlert(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = Field(default_factory=now_iso)
    kind: AlertKind
    title: str
    description: str
    indicators: List[str] = []           # URLs, phone numbers, handles, hashes, aliases
    severity: Literal["info", "warning", "danger", "critical"] = "warning"
    region: str = "Local Area"
    reporter_handle: str = "neighbourhood_watch"
    corroborations: int = 0
    status: Literal["active", "verified", "resolved"] = "active"


class CommunityAlertCreate(BaseModel):
    kind: AlertKind
    title: str
    description: str
    indicators: List[str] = []
    severity: Literal["info", "warning", "danger", "critical"] = "warning"
    region: str = "Local Area"
    reporter_handle: Optional[str] = "neighbour"


class FraudReportCreate(BaseModel):
    scheme_type: AlertKind
    perpetrator_alias: Optional[str] = None
    contact_indicators: List[str] = []   # phone / email / social handles / URLs / wallet / bank
    jurisdictions: List[str] = []        # states / regions where the scheme has operated
    amount_estimate: Optional[str] = None
    victims_count: int = 1
    narrative: str
    evidence_urls: List[str] = []
    reporter_contact: Optional[str] = None


class FraudReport(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = Field(default_factory=now_iso)
    case_ref: str
    scheme_type: AlertKind
    perpetrator_alias: Optional[str] = None
    contact_indicators: List[str] = []
    jurisdictions: List[str] = []
    amount_estimate: Optional[str] = None
    victims_count: int = 1
    narrative: str
    evidence_urls: List[str] = []
    reporter_contact: Optional[str] = None
    status: Literal["draft", "submitted", "escalated"] = "submitted"
    evidence_packet: Optional[str] = None


class RemediationJob(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = Field(default_factory=now_iso)
    device_id: str
    device_hostname: str
    status: Literal["running", "complete", "failed"] = "complete"
    threats_removed: int = 0
    steps: List[Dict[str, Any]] = []
    summary: str = ""


class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    user_id: str
    email: str
    name: str = ""
    picture: str = ""
    created_at: Optional[str] = None
