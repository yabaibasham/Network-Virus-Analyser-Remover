"""SentinelGrid Backend — application assembly.

Universal endpoint threat intelligence, LAN/WAN topology, community watch,
fraud reporting and authorised remediation. Route logic lives in ./routers/*.
"""
import os
import asyncio

from fastapi import FastAPI, APIRouter, Depends
from starlette.middleware.cors import CORSMiddleware

from database import client
from seed import ensure_seed
from routers.scanner import bootstrap_clamav
from routers.auth import get_current_user
from routers import (
    auth,
    stats,
    devices,
    incidents,
    scanner,
    network,
    community,
    fraud,
    remediation,
)

app = FastAPI(title="SentinelGrid API")

api_router = APIRouter(prefix="/api")

# Public routes (no authentication) — landing metrics + auth handshake
api_router.include_router(auth.router)
api_router.include_router(stats.router)

# Protected routes — require an authenticated Google session
_protected = (devices, incidents, scanner, network, community, fraud, remediation)
for module in _protected:
    api_router.include_router(module.router, dependencies=[Depends(get_current_user)])

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    await ensure_seed()
    asyncio.create_task(bootstrap_clamav())


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
