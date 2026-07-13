"""SentinelGrid backend E2E tests."""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    # Fallback: read frontend/.env
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL"):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")

API = f"{BASE_URL}/api"


TEST_TOKEN = "test_session_auditor_01"


@pytest.fixture(scope="session")
def s():
    sess = requests.Session()
    sess.headers.update({"Authorization": f"Bearer {TEST_TOKEN}"})
    return sess


@pytest.fixture(scope="session")
def anon():
    return requests.Session()


# ---------- stats ----------
def test_stats_has_new_fields(s):
    r = s.get(f"{API}/stats", timeout=30)
    assert r.status_code == 200
    d = r.json()
    for k in ["community_alerts", "blocklist_size", "fraud_reports", "remediations_run",
              "devices_total", "devices_infected", "open_incidents"]:
        assert k in d, f"missing {k}"
    assert isinstance(d["community_alerts"], int)


# ---------- network topology ----------
def test_network_topology(s):
    r = s.get(f"{API}/network/topology", timeout=30)
    assert r.status_code == 200
    d = r.json()
    assert "nodes" in d and "links" in d and "summary" in d
    sm = d["summary"]
    for k in ["endpoints", "subnets", "hostile_links", "gateway"]:
        assert k in sm
    kinds = {n["kind"] for n in d["nodes"]}
    assert "wan" in kinds and "gateway" in kinds and "subnet" in kinds and "endpoint" in kinds
    # Infected devices should produce threat + c2 link
    infected_present = any(n.get("status") == "infected" and n["kind"] == "endpoint" for n in d["nodes"])
    if infected_present:
        assert "threat" in kinds, "infected device should produce threat node"
        assert any(l.get("kind") == "c2" and l.get("status") == "hostile" for l in d["links"])
        assert sm["hostile_links"] >= 1


# ---------- community alerts ----------
def test_community_alerts_seeded(s):
    r = s.get(f"{API}/community/alerts", timeout=15)
    assert r.status_code == 200
    alerts = r.json()
    assert len(alerts) >= 5


def test_community_alert_create_and_corroborate(s):
    payload = {
        "kind": "phishing",
        "title": "TEST_ Phishing sms wave",
        "description": "TEST alert for E2E",
        "indicators": ["https://test-e2e-phish.top/x", "+1 555 000 9999"],
        "severity": "danger",
        "region": "TestRegion",
    }
    r = s.post(f"{API}/community/alerts", json=payload, timeout=15)
    assert r.status_code == 200, r.text
    alert = r.json()
    aid = alert["id"]
    assert alert["title"] == payload["title"]
    assert alert["status"] == "active"
    assert alert["corroborations"] == 0

    # Corroborate 5 times => verified
    last = None
    for _ in range(5):
        rr = s.post(f"{API}/community/alerts/{aid}/corroborate", timeout=10)
        assert rr.status_code == 200
        last = rr.json()
    assert last["corroborations"] == 5
    assert last["status"] == "verified"


def test_blocklist_aggregates(s):
    r = s.get(f"{API}/community/blocklist", timeout=15)
    assert r.status_code == 200
    d = r.json()
    assert "count" in d and "entries" in d
    assert d["count"] == len(d["entries"])
    assert d["count"] > 0
    ent = d["entries"][0]
    for k in ["indicator", "kind", "severity", "confirmations"]:
        assert k in ent


# ---------- fraud board ----------
def test_fraud_report_create_and_list(s):
    payload = {
        "scheme_type": "scam",
        "perpetrator_alias": "TEST_alias",
        "contact_indicators": ["+1 555 000 1111"],
        "jurisdictions": ["Testland"],
        "amount_estimate": "$500",
        "victims_count": 2,
        "narrative": "TEST narrative for fraud packet",
        "evidence_urls": ["https://example.com/x"],
        "reporter_contact": "test@example.com",
    }
    r = s.post(f"{API}/community/fraud-reports", json=payload, timeout=15)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["case_ref"].startswith("SG-")
    import re
    assert re.match(r"^SG-\d{6}-\d{4}$", rep["case_ref"])
    assert rep["evidence_packet"] and "SENTINELGRID" in rep["evidence_packet"]
    assert rep["case_ref"] in rep["evidence_packet"]

    r2 = s.get(f"{API}/community/fraud-reports", timeout=15)
    assert r2.status_code == 200
    assert any(x["case_ref"] == rep["case_ref"] for x in r2.json())


# ---------- devices regression ----------
def test_devices_list(s):
    r = s.get(f"{API}/devices", timeout=15)
    assert r.status_code == 200
    devs = r.json()
    assert len(devs) >= 10
    assert all("id" in d and "hostname" in d for d in devs)


def test_device_surface(s):
    devs = s.get(f"{API}/devices", timeout=15).json()
    did = devs[0]["id"]
    r = s.get(f"{API}/devices/{did}/surface", timeout=15)
    assert r.status_code == 200
    d = r.json()
    for k in ["device", "processes", "memory_blocks", "rat_checks", "network"]:
        assert k in d


def test_scan_url(s):
    r = s.post(f"{API}/scan", json={"target_type": "url", "target": "https://royal-parcel-redeliver.top/track"}, timeout=60)
    assert r.status_code == 200
    d = r.json()
    assert d["verdict"] in ["clean", "suspicious", "malicious"]
    assert 0 <= d["risk_score"] <= 100


def test_threat_logs(s):
    r = s.get(f"{API}/threat-logs", timeout=15)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_incidents(s):
    r = s.get(f"{API}/incidents", timeout=15)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ---------- remediation (run last) ----------
def test_z_remediation(s):
    # Pick an infected device
    devs = s.get(f"{API}/devices", timeout=15).json()
    infected = [d for d in devs if d["status"] == "infected"]
    if not infected:
        pytest.skip("no infected device to remediate (may have been cleaned)")
    target = infected[0]
    r = s.post(f"{API}/devices/{target['id']}/remediate", timeout=30)
    assert r.status_code == 200, r.text
    job = r.json()
    assert len(job["steps"]) == 8
    assert job["threats_removed"] >= 1
    assert job["status"] == "complete"

    # Device should be clean now
    dev2 = s.get(f"{API}/devices/{target['id']}", timeout=15).json()
    assert dev2["status"] == "clean"
    assert dev2["threats_detected"] == 0

    # Jobs list contains this one
    jobs = s.get(f"{API}/remediation/jobs", timeout=15).json()
    assert any(j["id"] == job["id"] for j in jobs)
