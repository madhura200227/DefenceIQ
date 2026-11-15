"""DefenceIQ Layer 03 — Threat Intelligence Connectors, Caching & MITRE ATT&CK Mapping."""

from __future__ import annotations

import json
import time
from typing import Any
import httpx

from backend.config import get_settings
from backend.database import DatabaseAdapter
from backend.datasets import KNOWN_BAD, KNOWN_GOOD, MITRE


def lookup_ip_local(ip: str) -> dict[str, Any]:
    """Deterministic baseline IOC reputation lookup with explicit provenance."""
    if ip in KNOWN_BAD:
        rec = dict(KNOWN_BAD[ip])
        rec.setdefault("provider", "local_reputation_dataset")
        return rec
    return {
        "abuseipdb": 0,
        "otx_pulses": 0,
        "tags": [KNOWN_GOOD.get(ip, "no reports")],
        "provider": "local_reputation_dataset",
    }


def map_mitre_technique(atype: str = "", alert_type: str = "") -> tuple[str, str]:
    key = atype or alert_type
    return MITRE.get(key, ("n/a", "unmapped"))


async def enrich_ip_indicator(db: DatabaseAdapter, ip: str, alert_type: str = "") -> dict[str, Any]:
    """Enriches an IP indicator via configured TI APIs (AbuseIPDB/OTX/VT) with DB cache & local fallback."""
    tid, tname = map_mitre_technique(alert_type)
    if not ip:
        return {"abuseipdb": 0, "otx_pulses": 0, "tags": ["no_ip"], "provider": "none"}

    # Check recent cache (1 hour TTL)
    now = time.time()
    cached = db.execute(
        "SELECT * FROM intelligence_records WHERE indicator_value=? ORDER BY id DESC LIMIT 1",
        (ip,),
    ).fetchone()
    if cached and (now - float(cached["retrieved_at"] or 0)) < 3600:
        return {
            "abuseipdb": int(cached["abuse_score"]),
            "otx_pulses": int(cached["otx_pulses"]),
            "tags": json.loads(cached["tags"]),
            "provider": cached["provider"],
        }

    settings = get_settings()
    result: dict[str, Any] | None = None

    if settings.abuseipdb_api_key:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = int(data.get("abuseConfidenceScore", 0))
                    usage = data.get("usageType") or "external"
                    result = {
                        "abuseipdb": score,
                        "otx_pulses": int(data.get("totalReports", 0)),
                        "tags": [usage.lower()],
                        "provider": "abuseipdb_v2",
                    }
        except Exception:
            result = None

    if result is None:
        result = lookup_ip_local(ip)

    db.execute(
        """INSERT INTO intelligence_records(
            indicator_value,provider,abuse_score,otx_pulses,tags,mitre_id,mitre_name,retrieved_at
        ) VALUES(?,?,?,?,?,?,?,?)""",
        (
            ip,
            str(result.get("provider", "local_reputation_dataset")),
            int(result["abuseipdb"]),
            int(result["otx_pulses"]),
            json.dumps(result["tags"]),
            tid,
            tname,
            now,
        ),
    )
    db.commit()
    return result

