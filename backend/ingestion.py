"""DefenceIQ Layer 01 — Data Ingestion, Validation & Idempotent Raw Event Store."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

from backend.database import DatabaseAdapter
from backend.schemas import IngestEventRequest


def compute_idempotency_key(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        {
            "id": payload.get("id", ""),
            "type": payload.get("type", ""),
            "user": payload.get("user", ""),
            "src_ip": payload.get("src_ip", ""),
            "host": payload.get("host", ""),
            "desc": payload.get("desc", ""),
            "t": payload.get("t", 0),
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def ingest_raw_event(
    db: DatabaseAdapter,
    req: IngestEventRequest | dict[str, Any],
    source_type: str = "json_webhook",
) -> dict[str, Any]:
    """Validates and stores an incoming event in `raw_events` with idempotency protection."""
    validated = req if isinstance(req, IngestEventRequest) else IngestEventRequest(**req)
    payload_dict = validated.model_dump()
    if isinstance(req, dict) and "label" in req:
        payload_dict["label"] = req["label"]

    idem_key = compute_idempotency_key(payload_dict)
    existing = db.execute(
        "SELECT * FROM raw_events WHERE idempotency_key=?",
        (idem_key,),
    ).fetchone()
    if existing:
        return {
            "raw_event_id": existing["id"],
            "alert_id": payload_dict.get("id") or existing["id"],
            "deduplicated": True,
            "received_at": existing["received_at"],
            "payload": json.loads(existing["raw_payload"]),
        }

    now = time.time()
    alert_id = payload_dict.get("id") or f"A-{uuid.uuid4().hex[:6].upper()}"
    payload_dict["id"] = alert_id
    raw_id = f"RAW-{alert_id}"

    db.execute(
        "INSERT OR IGNORE INTO raw_events(id,source_type,idempotency_key,raw_payload,received_at) VALUES(?,?,?,?,?)",
        (raw_id, validated.source_type or source_type, idem_key, json.dumps(payload_dict), now),
    )
    db.commit()

    return {
        "raw_event_id": raw_id,
        "alert_id": alert_id,
        "deduplicated": False,
        "received_at": now,
        "payload": payload_dict,
    }
