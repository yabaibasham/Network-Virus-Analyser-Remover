"""Backend regression tests for multi-tenancy org endpoints."""
import os
import uuid
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://malware-scanner-25.preview.emergentagent.com").rstrip("/")
AUDITOR_TOKEN = "test_session_auditor_01"
NEWORG_TOKEN = "test_session_neworg_01"


def _hdr(token):
    return {"Authorization": f"Bearer {token}"}


# --- helper: track created orgs so we can cleanup ---
CREATED_ORG_IDS = []


@pytest.fixture(scope="module", autouse=True)
def cleanup_orgs():
    yield
    # cleanup created orgs via mongo (test-only)
    try:
        import asyncio
        from motor.motor_asyncio import AsyncIOMotorClient
        from dotenv import load_dotenv
        load_dotenv("/app/backend/.env")
        db = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]

        async def _clean():
            for oid in CREATED_ORG_IDS:
                await db.orgs.delete_one({"org_id": oid})
                await db.memberships.delete_many({"org_id": oid})
                await db.invites.delete_many({"org_id": oid})
            # reset neworg user
            await db.users.update_one({"user_id": "user_neworg01"}, {"$set": {"active_org_id": None}})
            await db.memberships.delete_many({"user_id": "user_neworg01"})
            # ensure auditor active org back to demo
            await db.users.update_one({"user_id": "user_testauditor01"}, {"$set": {"active_org_id": "org_demo"}})

        asyncio.get_event_loop().run_until_complete(_clean())
    except Exception as e:
        print(f"cleanup err: {e}")


# --- Unauthenticated ---
class TestUnauth:
    def test_orgs_me_401(self):
        r = requests.get(f"{BASE_URL}/api/orgs/me")
        assert r.status_code == 401

    def test_devices_401(self):
        r = requests.get(f"{BASE_URL}/api/devices")
        assert r.status_code == 401

    def test_orgs_current_401(self):
        r = requests.get(f"{BASE_URL}/api/orgs/current")
        assert r.status_code == 401


# --- Auditor (has org) ---
class TestOrgsMeAuditor:
    def test_orgs_me_returns_shape(self):
        r = requests.get(f"{BASE_URL}/api/orgs/me", headers=_hdr(AUDITOR_TOKEN))
        assert r.status_code == 200
        data = r.json()
        assert "orgs" in data and "active_org_id" in data and "user" in data
        assert data["active_org_id"] == "org_demo"
        assert data["user"]["user_id"] == "user_testauditor01"
        org_demo = next((o for o in data["orgs"] if o["org_id"] == "org_demo"), None)
        assert org_demo is not None
        assert org_demo["name"] == "SentinelGrid Demo"
        assert org_demo["role"] == "owner"

    def test_orgs_current_members_and_invites(self):
        r = requests.get(f"{BASE_URL}/api/orgs/current", headers=_hdr(AUDITOR_TOKEN))
        assert r.status_code == 200
        data = r.json()
        assert data["role"] == "owner"
        assert isinstance(data["members"], list)
        assert any(m["user_id"] == "user_testauditor01" for m in data["members"])
        assert isinstance(data["invites"], list)

    def test_devices_scoped_to_active_org(self):
        r = requests.get(f"{BASE_URL}/api/devices", headers=_hdr(AUDITOR_TOKEN))
        assert r.status_code == 200
        devices = r.json()
        assert isinstance(devices, list)
        assert len(devices) >= 1  # demo fleet

    def test_stats_ok(self):
        r = requests.get(f"{BASE_URL}/api/stats", headers=_hdr(AUDITOR_TOKEN))
        assert r.status_code == 200

    def test_incidents_ok(self):
        r = requests.get(f"{BASE_URL}/api/incidents", headers=_hdr(AUDITOR_TOKEN))
        assert r.status_code == 200

    def test_threat_logs_ok(self):
        r = requests.get(f"{BASE_URL}/api/threat-logs", headers=_hdr(AUDITOR_TOKEN))
        assert r.status_code == 200


# --- New user (NO org) ---
class TestNoOrgUser:
    def test_orgs_me_returns_empty_orgs(self):
        r = requests.get(f"{BASE_URL}/api/orgs/me", headers=_hdr(NEWORG_TOKEN))
        assert r.status_code == 200
        data = r.json()
        assert data["orgs"] == []
        assert data["active_org_id"] in (None, "")

    def test_devices_409_no_active_org(self):
        r = requests.get(f"{BASE_URL}/api/devices", headers=_hdr(NEWORG_TOKEN))
        assert r.status_code == 409
        assert "No active" in r.json().get("detail", "")

    def test_incidents_409(self):
        r = requests.get(f"{BASE_URL}/api/incidents", headers=_hdr(NEWORG_TOKEN))
        assert r.status_code == 409

    def test_orgs_switch_forbidden_non_member(self):
        r = requests.post(
            f"{BASE_URL}/api/orgs/switch",
            headers=_hdr(NEWORG_TOKEN),
            json={"org_id": "org_demo"},
        )
        assert r.status_code == 403


# --- Create / Switch / Isolation ---
class TestCreateSwitchIsolate:
    def test_create_org_sets_active(self):
        name = f"TEST_{uuid.uuid4().hex[:6]}"
        r = requests.post(
            f"{BASE_URL}/api/orgs",
            headers=_hdr(NEWORG_TOKEN),
            json={"name": name, "org_type": "council", "region": "NT"},
        )
        assert r.status_code == 200
        org = r.json()
        assert org["name"] == name
        assert "org_id" in org
        CREATED_ORG_IDS.append(org["org_id"])
        # Verify via /orgs/me
        me = requests.get(f"{BASE_URL}/api/orgs/me", headers=_hdr(NEWORG_TOKEN)).json()
        assert me["active_org_id"] == org["org_id"]
        assert any(o["org_id"] == org["org_id"] and o["role"] == "owner" for o in me["orgs"])

    def test_new_org_has_empty_fleet(self):
        r = requests.get(f"{BASE_URL}/api/devices", headers=_hdr(NEWORG_TOKEN))
        assert r.status_code == 200
        assert r.json() == []

    def test_switch_to_non_member_org_forbidden(self):
        r = requests.post(
            f"{BASE_URL}/api/orgs/switch",
            headers=_hdr(NEWORG_TOKEN),
            json={"org_id": "org_demo"},
        )
        assert r.status_code == 403

    def test_switch_missing_org_id_400(self):
        r = requests.post(f"{BASE_URL}/api/orgs/switch", headers=_hdr(NEWORG_TOKEN), json={})
        assert r.status_code == 400


# --- Invites ---
class TestInvites:
    def test_invite_non_existing_email_creates_pending(self):
        email = f"test_new_{uuid.uuid4().hex[:6]}@example.com"
        r = requests.post(
            f"{BASE_URL}/api/orgs/invite",
            headers=_hdr(AUDITOR_TOKEN),
            json={"email": email, "role": "analyst"},
        )
        assert r.status_code == 200
        invite_id = r.json()["invite_id"]
        # Verify via /orgs/current
        cur = requests.get(f"{BASE_URL}/api/orgs/current", headers=_hdr(AUDITOR_TOKEN)).json()
        assert any(i["email"] == email and i["role"] == "analyst" for i in cur["invites"])
        # Revoke
        r2 = requests.delete(f"{BASE_URL}/api/orgs/invites/{invite_id}", headers=_hdr(AUDITOR_TOKEN))
        assert r2.status_code == 200
        cur2 = requests.get(f"{BASE_URL}/api/orgs/current", headers=_hdr(AUDITOR_TOKEN)).json()
        assert not any(i["id"] == invite_id for i in cur2["invites"])

    def test_invite_existing_user_adds_immediately(self):
        # First ensure user_neworg01 is not a member of org_demo
        # Invite by email
        r = requests.post(
            f"{BASE_URL}/api/orgs/invite",
            headers=_hdr(AUDITOR_TOKEN),
            json={"email": "neworg@sentinelgrid.local", "role": "viewer"},
        )
        assert r.status_code == 200
        cur = requests.get(f"{BASE_URL}/api/orgs/current", headers=_hdr(AUDITOR_TOKEN)).json()
        assert any(m["user_id"] == "user_neworg01" and m["role"] == "viewer" for m in cur["members"])
        # cleanup: remove that membership
        r_rm = requests.delete(
            f"{BASE_URL}/api/orgs/members/user_neworg01", headers=_hdr(AUDITOR_TOKEN)
        )
        assert r_rm.status_code == 200

    def test_invite_bad_email_400(self):
        r = requests.post(
            f"{BASE_URL}/api/orgs/invite",
            headers=_hdr(AUDITOR_TOKEN),
            json={"email": "notanemail", "role": "analyst"},
        )
        assert r.status_code == 400


# --- Last-owner guards ---
class TestOwnerGuards:
    def test_cannot_demote_last_owner(self):
        r = requests.post(
            f"{BASE_URL}/api/orgs/members/user_testauditor01/role",
            headers=_hdr(AUDITOR_TOKEN),
            json={"role": "viewer"},
        )
        assert r.status_code == 400
        assert "last owner" in r.json().get("detail", "").lower()

    def test_cannot_remove_last_owner(self):
        r = requests.delete(
            f"{BASE_URL}/api/orgs/members/user_testauditor01", headers=_hdr(AUDITOR_TOKEN)
        )
        assert r.status_code == 400
