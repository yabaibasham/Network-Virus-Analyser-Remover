"""Organisations: onboarding, switching, membership + invites."""
from fastapi import APIRouter, Depends, HTTPException

from database import db, SUPERADMIN_EMAILS
from models import Org, OrgCreate, OrgSwitch, Membership, Invite, InviteCreate, RoleUpdate
from routers.auth import get_current_user
from context import get_current_context, ensure_owner

router = APIRouter()


@router.get("/orgs/me")
async def my_orgs(user=Depends(get_current_user)):
    superadmin = user.email.lower() in SUPERADMIN_EMAILS
    orgs = []
    if superadmin:
        docs = await db.orgs.find({}, {"_id": 0}).to_list(500)
        for o in docs:
            m = await db.memberships.find_one({"org_id": o["org_id"], "user_id": user.user_id})
            orgs.append({"org_id": o["org_id"], "name": o["name"], "org_type": o.get("org_type"),
                         "region": o.get("region"), "role": (m["role"] if m else "owner")})
    else:
        mems = await db.memberships.find({"user_id": user.user_id}, {"_id": 0}).to_list(200)
        for m in mems:
            o = await db.orgs.find_one({"org_id": m["org_id"]}, {"_id": 0})
            if o:
                orgs.append({"org_id": o["org_id"], "name": o["name"], "org_type": o.get("org_type"),
                             "region": o.get("region"), "role": m["role"]})
    return {
        "orgs": orgs,
        "active_org_id": user.active_org_id,
        "superadmin": superadmin,
        "user": {"user_id": user.user_id, "email": user.email, "name": user.name, "picture": user.picture},
    }


@router.post("/orgs")
async def create_org(payload: OrgCreate, user=Depends(get_current_user)):
    org = Org(name=payload.name.strip() or "My Organisation", org_type=payload.org_type,
              region=payload.region, owner_user_id=user.user_id)
    await db.orgs.insert_one(org.model_dump())
    await db.memberships.insert_one(
        Membership(org_id=org.org_id, user_id=user.user_id, role="owner").model_dump()
    )
    await db.users.update_one({"user_id": user.user_id}, {"$set": {"active_org_id": org.org_id}})
    return org.model_dump()


@router.post("/orgs/switch")
async def switch_org(payload: OrgSwitch, user=Depends(get_current_user)):
    org_id = payload.org_id.strip()
    if not org_id:
        raise HTTPException(400, "org_id required")
    superadmin = user.email.lower() in SUPERADMIN_EMAILS
    member = await db.memberships.find_one({"org_id": org_id, "user_id": user.user_id})
    if not member and not superadmin:
        raise HTTPException(403, "Not a member of this organisation")
    org = await db.orgs.find_one({"org_id": org_id})
    if not org:
        raise HTTPException(404, "Organisation not found")
    await db.users.update_one({"user_id": user.user_id}, {"$set": {"active_org_id": org_id}})
    return {"ok": True, "active_org_id": org_id}


@router.get("/orgs/current")
async def current_org(ctx=Depends(get_current_context)):
    org_id = ctx["org_id"]
    mems = await db.memberships.find({"org_id": org_id}, {"_id": 0}).to_list(500)
    members = []
    for m in mems:
        u = await db.users.find_one({"user_id": m["user_id"]}, {"_id": 0}) or {}
        members.append({"user_id": m["user_id"], "email": u.get("email"),
                        "name": u.get("name"), "role": m["role"]})
    invites = []
    if ctx["role"] == "owner" or ctx["superadmin"]:
        inv = await db.invites.find({"org_id": org_id, "status": "pending"}, {"_id": 0}).to_list(200)
        invites = [{"id": i["id"], "email": i["email"], "role": i["role"]} for i in inv]
    return {"org": ctx["org"], "role": ctx["role"], "superadmin": ctx["superadmin"],
            "members": members, "invites": invites}


@router.post("/orgs/invite")
async def invite_member(payload: InviteCreate, ctx=Depends(get_current_context)):
    ensure_owner(ctx)
    email = payload.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(400, "Valid email required")
    existing = await db.invites.find_one({"org_id": ctx["org_id"], "email": email, "status": "pending"})
    if existing:
        await db.invites.update_one({"id": existing["id"]}, {"$set": {"role": payload.role}})
        invite_id = existing["id"]
    else:
        inv = Invite(org_id=ctx["org_id"], email=email, role=payload.role, invited_by=ctx["user"].user_id)
        await db.invites.insert_one(inv.model_dump())
        invite_id = inv.id
    # If the invitee already has an account, add them immediately.
    u = await db.users.find_one({"email": email}, {"_id": 0})
    if u:
        exists = await db.memberships.find_one({"org_id": ctx["org_id"], "user_id": u["user_id"]})
        if not exists:
            await db.memberships.insert_one(
                Membership(org_id=ctx["org_id"], user_id=u["user_id"], role=payload.role).model_dump()
            )
        await db.invites.update_one({"id": invite_id}, {"$set": {"status": "accepted"}})
    return {"ok": True, "invite_id": invite_id}


@router.delete("/orgs/invites/{invite_id}")
async def revoke_invite(invite_id: str, ctx=Depends(get_current_context)):
    ensure_owner(ctx)
    await db.invites.delete_one({"id": invite_id, "org_id": ctx["org_id"]})
    return {"ok": True}


@router.post("/orgs/members/{user_id}/role")
async def change_role(user_id: str, payload: RoleUpdate, ctx=Depends(get_current_context)):
    ensure_owner(ctx)
    m = await db.memberships.find_one({"org_id": ctx["org_id"], "user_id": user_id})
    if not m:
        raise HTTPException(404, "Member not found")
    if m["role"] == "owner" and payload.role != "owner":
        owners = await db.memberships.count_documents({"org_id": ctx["org_id"], "role": "owner"})
        if owners <= 1:
            raise HTTPException(400, "Cannot demote the last owner")
    await db.memberships.update_one(
        {"org_id": ctx["org_id"], "user_id": user_id}, {"$set": {"role": payload.role}}
    )
    return {"ok": True, "role": payload.role}


@router.delete("/orgs/members/{user_id}")
async def remove_member(user_id: str, ctx=Depends(get_current_context)):
    ensure_owner(ctx)
    m = await db.memberships.find_one({"org_id": ctx["org_id"], "user_id": user_id})
    if not m:
        raise HTTPException(404, "Member not found")
    if m["role"] == "owner":
        owners = await db.memberships.count_documents({"org_id": ctx["org_id"], "role": "owner"})
        if owners <= 1:
            raise HTTPException(400, "Cannot remove the last owner")
    await db.memberships.delete_one({"org_id": ctx["org_id"], "user_id": user_id})
    # If that user was pointed at this org, clear their active org.
    await db.users.update_one(
        {"user_id": user_id, "active_org_id": ctx["org_id"]}, {"$set": {"active_org_id": None}}
    )
    return {"ok": True}
