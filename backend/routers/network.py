"""LAN / WAN network topology derived from the org's fleet."""
import random
from typing import List, Dict, Any

from fastapi import APIRouter, Depends

from database import db, now_iso
from models import Device
from context import get_current_context

router = APIRouter()


@router.get("/network/topology")
async def network_topology(ctx=Depends(get_current_context)):
    docs = await db.devices.find({"org_id": ctx["org_id"]}, {"_id": 0}).to_list(500)
    devices = [Device(**d) for d in docs]

    nodes: List[Dict[str, Any]] = [
        {"id": "wan", "label": "WAN · INTERNET", "kind": "wan", "status": "clean"}
    ]
    links: List[Dict[str, Any]] = []

    gateway = next((d for d in devices if d.device_type == "router"), None)
    gw_id = "gateway"
    nodes.append({
        "id": gw_id,
        "label": gateway.hostname if gateway else "edge-gateway",
        "kind": "gateway",
        "ip": gateway.ip_address if gateway else "10.0.0.1",
        "status": gateway.status if gateway else "clean",
    })
    links.append({"source": "wan", "target": gw_id, "kind": "uplink", "status": "clean"})

    subnets: Dict[str, List[Device]] = {}
    for d in devices:
        if gateway and d.id == gateway.id:
            continue
        octets = d.ip_address.split(".")
        subnet = (".".join(octets[:3]) + ".0/24") if len(octets) >= 3 else "unknown"
        subnets.setdefault(subnet, []).append(d)

    hostile_links = 0
    for subnet in sorted(subnets.keys()):
        members = subnets[subnet]
        sub_id = f"subnet:{subnet}"
        seg_infected = any(m.status == "infected" for m in members)
        nodes.append({
            "id": sub_id, "label": subnet, "kind": "subnet",
            "status": "infected" if seg_infected else "clean", "count": len(members),
        })
        links.append({"source": gw_id, "target": sub_id, "kind": "lan", "status": "clean"})
        for m in members:
            nodes.append({
                "id": m.id, "label": m.hostname, "kind": "endpoint",
                "device_type": m.device_type, "ip": m.ip_address, "os": m.os,
                "location": m.location, "status": m.status, "threats": m.threats_detected,
            })
            links.append({"source": sub_id, "target": m.id, "kind": "endpoint", "status": m.status})
            if m.status == "infected":
                rng = random.Random(m.fingerprint)
                c2_id = f"c2:{m.id[:8]}"
                nodes.append({
                    "id": c2_id,
                    "label": f"185.220.{rng.randint(0,255)}.{rng.randint(1,254)}:4444",
                    "kind": "threat", "status": "hostile",
                })
                links.append({"source": m.id, "target": c2_id, "kind": "c2", "status": "hostile"})
                hostile_links += 1

    return {
        "nodes": nodes,
        "links": links,
        "summary": {
            "endpoints": sum(1 for n in nodes if n["kind"] == "endpoint"),
            "subnets": len(subnets),
            "hostile_links": hostile_links,
            "gateway": gateway.hostname if gateway else "edge-gateway",
        },
        "generated_at": now_iso(),
    }
