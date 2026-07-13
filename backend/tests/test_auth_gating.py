"""SentinelGrid — auth gating & session tests (SEC-001/002/003)."""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL"):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")

API = f"{BASE_URL}/api"
TOKEN = "test_session_auditor_01"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


# ---------- public endpoints (must be 200 without auth) ----------
@pytest.mark.parametrize("path", ["/", "/stats"])
def test_public_endpoints_no_auth(path):
    r = requests.get(f"{API}{path}", timeout=15)
    assert r.status_code == 200, f"{path} -> {r.status_code}"


# ---------- protected GETs return 401 without auth ----------
PROTECTED_GETS = [
    "/devices",
    "/threat-logs",
    "/incidents",
    "/network/topology",
    "/community/alerts",
    "/community/blocklist",
    "/community/fraud-reports",
    "/remediation/jobs",
    "/auth/me",
]


@pytest.mark.parametrize("path", PROTECTED_GETS)
def test_protected_get_unauth_401(path):
    r = requests.get(f"{API}{path}", timeout=15)
    assert r.status_code == 401, f"{path} expected 401, got {r.status_code}"


@pytest.mark.parametrize("path", PROTECTED_GETS)
def test_protected_get_with_auth_200(path):
    r = requests.get(f"{API}{path}", headers=AUTH, timeout=30)
    assert r.status_code == 200, f"{path} expected 200 w/ auth, got {r.status_code} :: {r.text[:200]}"


# ---------- mutating endpoints require auth (401 without) ----------
def test_mutating_endpoints_require_auth():
    devs = requests.get(f"{API}/devices", headers=AUTH, timeout=15).json()
    did = devs[0]["id"]
    inc = requests.get(f"{API}/incidents", headers=AUTH, timeout=15).json()
    iid = inc[0]["id"] if inc else None

    cases = [
        ("POST", f"/devices/{did}/action", {"action": "isolate"}),
        ("POST", f"/devices/{did}/remediate", None),
        ("POST", f"/devices/{did}/report-missing", {}),
        ("POST", "/community/alerts", {}),
        ("POST", "/community/fraud-reports", {}),
    ]
    if iid:
        cases.append(("POST", f"/incidents/{iid}/status", {"status": "acknowledged"}))

    for method, path, body in cases:
        r = requests.request(method, f"{API}{path}", json=body, timeout=15)
        assert r.status_code == 401, f"{method} {path} expected 401, got {r.status_code}"


# ---------- auth/me + logout ----------
def test_auth_me_returns_user():
    r = requests.get(f"{API}/auth/me", headers=AUTH, timeout=15)
    assert r.status_code == 200
    d = r.json()
    assert d["email"] == "auditor@sentinelgrid.local"
    assert d["user_id"] == "user_testauditor01"


def test_auth_me_no_token_401():
    r = requests.get(f"{API}/auth/me", timeout=15)
    assert r.status_code == 401


def test_auth_logout_ok():
    # Logout without token should still 200 (idempotent)
    r = requests.post(f"{API}/auth/logout", timeout=15)
    assert r.status_code == 200
    assert r.json().get("ok") is True


# ---------- upload SEC-003: EICAR + clean ----------
def test_upload_eicar_malicious():
    eicar = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    files = {"file": ("eicar.txt", eicar.encode(), "text/plain")}
    r = requests.post(f"{API}/scan/upload", headers=AUTH, files=files, timeout=60)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["verdict"] == "malicious"
    assert d.get("clamav_summary") and "Eicar" in d["clamav_summary"].get("signature", "")
    assert d.get("circl_summary") is not None


def test_upload_clean_file():
    files = {"file": ("hello.txt", b"hello world clean file", "text/plain")}
    r = requests.post(f"{API}/scan/upload", headers=AUTH, files=files, timeout=60)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["verdict"] == "clean"
    assert d.get("circl_summary") is not None


def test_upload_requires_auth():
    files = {"file": ("hello.txt", b"data", "text/plain")}
    r = requests.post(f"{API}/scan/upload", files=files, timeout=30)
    assert r.status_code == 401


# ---------- threat intel presence on url scan ----------
def test_scan_url_has_circl_summary():
    r = requests.post(
        f"{API}/scan",
        headers=AUTH,
        json={"target_type": "url", "target": "https://royal-parcel-redeliver.top/track"},
        timeout=60,
    )
    assert r.status_code == 200
    d = r.json()
    # circl_summary present (may be None for URL target since no hash) — assert key exists
    assert "circl_summary" in d
    assert d["verdict"] in ["clean", "suspicious", "malicious"]
