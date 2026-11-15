"""DefenceIQ Layer 02 — Schema Normalization, IOC Extraction & Deterministic Correlation Engine."""

from __future__ import annotations

import time
from typing import Any

from backend.database import DatabaseAdapter
from backend.schemas import NormalizedEventSchema


def infer_baseline_severity(event_type: str, explicit: str | None = None) -> str:
    if explicit in ("low", "medium", "high"):
        return explicit
    high_types = {"bruteforce_then_success", "large_outbound_transfer"}
    med_types = {"failed_login_burst", "impossible_travel"}
    if event_type in high_types:
        return "high"
    if event_type in med_types:
        return "medium"
    return "low"


def normalize_and_extract(
    db: DatabaseAdapter,
    raw_event_id: str,
    alert_payload: dict[str, Any],
) -> NormalizedEventSchema:
    """Normalizes raw payload into internal event schema and extracts IOC indicators."""
    now = time.time()
    alert_id = str(alert_payload["id"])
    norm_id = f"NORM-{alert_id}"
    ev_type = str(alert_payload.get("type", "unknown"))
    sev = infer_baseline_severity(ev_type, alert_payload.get("severity"))
    src_ip = str(alert_payload.get("src_ip", ""))
    user = str(alert_payload.get("user", ""))
    host = str(alert_payload.get("host", ""))
    desc = str(alert_payload.get("desc", ""))
    offset = int(alert_payload.get("t", 0))

    db.execute(
        """INSERT OR IGNORE INTO normalized_events(
            id,raw_event_id,event_type,severity,src_ip,username,hostname,description,scenario_offset,occurred_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (norm_id, raw_event_id, ev_type, sev, src_ip, user, host, desc, offset, now),
    )

    # Extract IOCs (ip, user, host)
    for ioc_type, ioc_val in (("ip", src_ip), ("user", user), ("host", host)):
        if ioc_val:
            db.execute(
                "INSERT INTO indicators(incident_id,alert_id,indicator_type,indicator_value) VALUES(?,?,?,?)",
                ("", alert_id, ioc_type, ioc_val),
            )
    db.commit()

    return NormalizedEventSchema(
        id=norm_id,
        raw_event_id=raw_event_id,
        event_type=ev_type,
        severity=sev,  # type: ignore[arg-type]
        src_ip=src_ip,
        username=user,
        hostname=host,
        description=desc,
        scenario_offset=offset,
        occurred_at=now,
    )


def correlate_alert_to_incident(
    db: DatabaseAdapter,
    alert_payload: dict[str, Any],
    escalated: bool,
    severity: str,
) -> str | None:
    """Deterministic entity & time-window correlation into unified Incident candidates."""
    if not escalated:
        return None

    alert_id = str(alert_payload["id"])
    user = str(alert_payload.get("user", "")).strip()
    src_ip = str(alert_payload.get("src_ip", "")).strip()
    host = str(alert_payload.get("host", "")).strip()
    desc = str(alert_payload.get("desc", ""))
    now = time.time()

    # Deterministic correlation key: shared compromised principal or shared external source IP
    corr_entity = user if user else (src_ip if src_ip else alert_id)
    safe_slug = "".join(c if c.isalnum() else "-" for c in corr_entity).strip("-").upper()
    incident_id = f"INC-{safe_slug}"

    existing = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if existing:
        # Update priority if higher severity observed
        rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        new_priority = severity if rank.get(severity, 1) > rank.get(existing["priority"], 1) else existing["priority"]
        rationale = (
            f"{existing['correlation_rationale']}; correlated {alert_id} ({alert_payload.get('type')}) "
            f"on host {host} via shared entity '{corr_entity}'"
        )
        db.execute(
            "UPDATE incidents SET priority=?, correlation_rationale=?, updated_at=? WHERE id=?",
            (new_priority, rationale, now, incident_id),
        )
    else:
        rationale = (
            f"Incident candidate initialized from {alert_id} ({alert_payload.get('type')}) "
            f"keyed on entity '{corr_entity}' (src_ip={src_ip}, host={host})"
        )
        title = f"Correlated intrusion activity involving {corr_entity}: {desc}"
        db.execute(
            """INSERT INTO incidents(
                id,title,status,priority,risk_score,risk_breakdown,correlation_rationale,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (incident_id, title, "investigating", severity, 0.0, "{}", rationale, now, now),
        )

    db.execute("UPDATE alerts SET incident_id=? WHERE id=?", (incident_id, alert_id))
    db.execute("UPDATE indicators SET incident_id=? WHERE alert_id=?", (incident_id, alert_id))
    db.commit()
    return incident_id
