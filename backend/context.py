"""Tenant context: resolves the current user's active organisation + role."""
from fastapi import Request, HTTPException

from database import db, SUPERADMIN_EMAILS
from routers.auth import get_current_user


async def get_current_context(request: Request) -> dict:
    """Return {user, org_id, role, superadmin, org}. Enforces auth + active org."""
    user = await get_current_user(request)
    superadmin = user.email.lower() in SUPERADMIN_EMAILS
    org_id = user.active_org_id
    if not org_id:
        raise HTTPException(status_code=409, detail="No active organisation")
    org = await db.orgs.find_one({"org_id": org_id}, {"_id": 0})
    if not org:
        raise HTTPException(status_code=409, detail="Organisation not found")
    membership = await db.memberships.find_one(
        {"org_id": org_id, "user_id": user.user_id}, {"_id": 0}
    )
    if membership:
        role = membership["role"]
    elif superadmin:
        role = "owner"  # platform super-admin has full access to any org
    else:
        raise HTTPException(status_code=403, detail="Not a member of this organisation")
    return {"user": user, "org_id": org_id, "role": role, "superadmin": superadmin, "org": org}


def ensure_write(ctx: dict):
    if ctx["role"] not in ("owner", "analyst"):
        raise HTTPException(status_code=403, detail="Your role is read-only (Viewer)")


def ensure_owner(ctx: dict):
    if ctx["role"] != "owner" and not ctx["superadmin"]:
        raise HTTPException(status_code=403, detail="Owner permission required")
