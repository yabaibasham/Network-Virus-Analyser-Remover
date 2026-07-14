"""Shared infra: env loading, Mongo client, logger, time helper."""
import os
import logging
from pathlib import Path
from datetime import datetime, timezone

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

EMERGENT_LLM_KEY = os.environ.get("EMERGENT_LLM_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")  # optional
SUPERADMIN_EMAILS = {
    e.strip().lower() for e in os.environ.get("SUPERADMIN_EMAILS", "").split(",") if e.strip()
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("sentinelgrid")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
