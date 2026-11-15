"""DefenceIQ Layer 06 — Enterprise REST API v1 Router (/api/v1/*)."""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from backend.config import get_settings
from backend.database import compute_audit_hash
from backend.ingestion import ingest_raw_event
from backend.normalization import normalize_and_extract
from backend.orchestrator import DB, resolve_approval_decision, run
from backend.schemas import (
    IncidentCreateRequest,
    IngestEventRequest,
    RecommendationDecisionRequest,
)

v1_router = APIRouter(prefix="/api/v1", tags=["v1"])


def _verify_audit_chain(rows: list[dict[str, Any]]) -> bool:
    """Verifies the cryptographic SHA-256 hash chain across ordered audit rows."""
    expected_prev = "GENESIS"
    for r in rows:
        prev_h = r.get("prev_hash") or "GENESIS"
        row_h = r.get("row_hash") or ""
        if not row_h:
            continue
        if prev_h != expected_prev:
            return False
        data_raw = r.get("data") if isinstance(r.get("data"), str) else json.dumps(r.get("data") or {}, sort_keys=True)
        computed = compute_audit_hash(
            prev_h,
            float(r["ts"]),
            str(r["alert_id"]),
            str(r["agent"]),
            str(r["kind"]),
            str(r["msg"]),
            data_raw,
        )
        if computed != row_h:
            return False
        expected_prev = row_h
    return True


@v1_router.get("/health")
def health_check() -> dict[str, Any]:
    settings = get_settings()
    gemini_key = os.getenv("GEMINI_API_KEY", settings.gemini_api_key)
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", settings.anthropic_api_key)
    alerts_cnt = DB.execute("SELECT COUNT(*) AS cnt FROM alerts").fetchone()
    incidents_cnt = DB.execute("SELECT COUNT(*) AS cnt FROM incidents").fetchone()
    audit_cnt = DB.execute("SELECT COUNT(*) AS cnt FROM audit").fetchone()
    return {
        "status": "ok",
        "database_backend": "postgresql" if DB.is_postgres else "sqlite",
        "llm_providers": {
            "gemini_configured": bool(gemini_key),
            "anthropic_configured": bool(anthropic_key),
            "active_mode": (
                "gemini"
                if gemini_key
                else "anthropic"
                if anthropic_key
                else "deterministic_heuristic_fallback"
            ),
        },
        "counts": {
            "alerts": int((alerts_cnt or {}).get("cnt") or 0),
            "incidents": int((incidents_cnt or {}).get("cnt") or 0),
            "audit_events": int((audit_cnt or {}).get("cnt") or 0),
        },
    }


@v1_router.post("/events/ingest")
async def ingest_event_endpoint(req: IngestEventRequest) -> dict[str, Any]:
    alert_dict = {
        "id": req.id or f"A-{uuid.uuid4().hex[:6].upper()}",
        "t": req.t,
        "type": req.type,
        "user": req.user,
        "src_ip": req.src_ip,
        "host": req.host,
        "desc": req.desc,
    }
    ingested = ingest_raw_event(DB, alert_dict, source_type=req.source_type)
    alert_id = ingested["alert_id"]
    alert_dict["id"] = alert_id

    if not ingested["deduplicated"]:
        norm = normalize_and_extract(DB, ingested["raw_event_id"], alert_dict)
        DB.execute(
            "INSERT OR IGNORE INTO alerts(id,raw,status,severity,created_at) VALUES(?,?,'new',?,?)",
            (alert_id, json.dumps(alert_dict), req.severity or norm.severity, time.time()),
        )
        DB.commit()
        if req.run_pipeline:
            asyncio.create_task(run(alert_dict))

    return {
        "status": "accepted" if not ingested["deduplicated"] else "deduplicated",
        "raw_event_id": ingested["raw_event_id"],
        "alert_id": alert_id,
        "payload_hash": ingested["payload_hash"],
        "deduplicated": ingested["deduplicated"],
    }


@v1_router.get("/events")
def list_normalized_events(
    severity: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    clauses: list[str] = []
    params: list[Any] = []
    if severity:
        clauses.append("severity=?")
        params.append(severity)
    if event_type:
        clauses.append("event_type=?")
        params.append(event_type)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"SELECT * FROM normalized_events {where_sql} ORDER BY occurred_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = DB.execute(sql, tuple(params)).fetchall()
    return {"items": rows, "count": len(rows), "limit": limit, "offset": offset}


@v1_router.get("/incidents")
def list_incidents(
    status: str | None = Query(default=None),
    priority: str | None = Query(default=None),
) -> dict[str, Any]:
    clauses: list[str] = []
    params: list[Any] = []
    if status:
        clauses.append("status=?")
        params.append(status)
    if priority:
        clauses.append("priority=?")
        params.append(priority)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = DB.execute(f"SELECT * FROM incidents {where_sql} ORDER BY updated_at DESC", tuple(params)).fetchall()
    items = []
    for r in rows:
        alert_rows = DB.execute("SELECT id FROM alerts WHERE incident_id=? ORDER BY id", (r["id"],)).fetchall()
        items.append(
            {
                **r,
                "risk_breakdown": json.loads(r["risk_breakdown"] or "{}"),
                "alert_ids": [a["id"] for a in alert_rows],
            }
        )
    return {"items": items, "count": len(items)}


@v1_router.post("/incidents")
def create_manual_incident(req: IncidentCreateRequest) -> dict[str, Any]:
    inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    now = time.time()
    DB.execute(
        """INSERT INTO incidents(
            id,title,status,priority,risk_score,risk_breakdown,correlation_rationale,created_at,updated_at
        ) VALUES(?,?,?,?,?,?,?,?,?)""",
        (
            inc_id,
            req.title,
            "investigating",
            req.priority,
            50.0,
            json.dumps({"manual": True, "metadata": req.metadata}),
            req.rationale,
            now,
            now,
        ),
    )
    for aid in req.alert_ids:
        DB.execute("UPDATE alerts SET incident_id=? WHERE id=?", (inc_id, aid))
    DB.commit()
    return {
        "id": inc_id,
        "title": req.title,
        "status": "investigating",
        "priority": req.priority,
        "alert_ids": req.alert_ids,
        "created_at": now,
    }


def _resolve_incident_or_alert_ids(incident_id: str) -> tuple[str, list[str]]:
    """Allows querying /api/v1/incidents/{id}/* by either incident_id (INC-*) or alert_id (A-*)."""
    inc = DB.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if inc:
        alerts = DB.execute("SELECT id FROM alerts WHERE incident_id=? ORDER BY id", (incident_id,)).fetchall()
        aids = [a["id"] for a in alerts]
        if not aids and incident_id.startswith("INC-A-"):
            aids = [incident_id.replace("INC-", "", 1)]
        return incident_id, aids

    alert_row = DB.execute("SELECT * FROM alerts WHERE id=?", (incident_id,)).fetchone()
    if alert_row:
        real_inc = alert_row.get("incident_id") or f"INC-{incident_id}"
        return real_inc, [incident_id]

    raise HTTPException(status_code=404, detail=f"Incident or alert '{incident_id}' not found")


@v1_router.get("/incidents/{incident_id}")
def get_incident_detail(incident_id: str) -> dict[str, Any]:
    real_inc_id, alert_ids = _resolve_incident_or_alert_ids(incident_id)
    inc = DB.execute("SELECT * FROM incidents WHERE id=?", (real_inc_id,)).fetchone()
    alerts = []
    for aid in alert_ids:
        arow = DB.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
        if arow:
            alerts.append({**arow, "raw": json.loads(arow["raw"])})

    if not inc and alerts:
        first = alerts[0]
        return {
            "id": real_inc_id,
            "title": first["raw"].get("desc", real_inc_id),
            "status": first["status"],
            "priority": first.get("severity") or "low",
            "risk_score": 0.0,
            "risk_breakdown": {},
            "alerts": alerts,
        }

    return {
        **inc,
        "risk_breakdown": json.loads(inc["risk_breakdown"] or "{}"),
        "alerts": alerts,
    }


@v1_router.get("/incidents/{incident_id}/evidence")
def get_incident_evidence(incident_id: str) -> dict[str, Any]:
    real_inc_id, alert_ids = _resolve_incident_or_alert_ids(incident_id)
    rows = DB.execute(
        "SELECT * FROM evidence WHERE incident_id=? ORDER BY id ASC",
        (real_inc_id,),
    ).fetchall()
    if not rows and alert_ids:
        placeholders = ",".join("?" for _ in alert_ids)
        rows = DB.execute(
            f"SELECT * FROM evidence WHERE alert_id IN ({placeholders}) ORDER BY id ASC",
            tuple(alert_ids),
        ).fetchall()
    items = []
    for r in rows:
        refs = json.loads(r.get("source_refs") or "[]")
        items.append(
            {
                **r,
                "source_refs": refs,
                "citations": refs,
                "verified": bool(r["verified"]),
            }
        )
    return {"incident_id": real_inc_id, "items": items, "count": len(items)}


@v1_router.get("/incidents/{incident_id}/timeline")
def get_incident_timeline(incident_id: str) -> dict[str, Any]:
    real_inc_id, alert_ids = _resolve_incident_or_alert_ids(incident_id)
    if not alert_ids:
        return {"incident_id": real_inc_id, "timeline": [], "audit_events": []}
    placeholders = ",".join("?" for _ in alert_ids)
    audit_rows = DB.execute(
        f"SELECT * FROM audit WHERE alert_id IN ({placeholders}) ORDER BY n ASC",
        tuple(alert_ids),
    ).fetchall()
    timeline_lines: list[str] = []
    parsed_audit = []
    for r in audit_rows:
        data_obj = json.loads(r["data"] or "{}")
        parsed_audit.append({**r, "data": data_obj})
        if r["kind"] == "timeline" and isinstance(data_obj.get("timeline"), list):
            timeline_lines.extend(data_obj["timeline"])
    return {
        "incident_id": real_inc_id,
        "alert_ids": alert_ids,
        "timeline": timeline_lines,
        "audit_events": parsed_audit,
    }


@v1_router.get("/incidents/{incident_id}/analysis")
def get_incident_analysis(incident_id: str) -> dict[str, Any]:
    real_inc_id, alert_ids = _resolve_incident_or_alert_ids(incident_id)
    rows = DB.execute(
        "SELECT * FROM agent_runs WHERE incident_id=? ORDER BY id ASC",
        (real_inc_id,),
    ).fetchall()
    if not rows and alert_ids:
        placeholders = ",".join("?" for _ in alert_ids)
        rows = DB.execute(
            f"SELECT * FROM agent_runs WHERE alert_id IN ({placeholders}) ORDER BY id ASC",
            tuple(alert_ids),
        ).fetchall()
    items = []
    for r in rows:
        env = json.loads(r.get("output") or "{}")
        items.append({**r, "output": env, "envelope": env})
    return {"incident_id": real_inc_id, "agent_runs": items, "count": len(items)}


@v1_router.get("/incidents/{incident_id}/recommendations")
def get_incident_recommendations(incident_id: str) -> dict[str, Any]:
    real_inc_id, alert_ids = _resolve_incident_or_alert_ids(incident_id)
    rows = DB.execute(
        "SELECT * FROM recommendations WHERE incident_id=? ORDER BY created_at ASC",
        (real_inc_id,),
    ).fetchall()
    if not rows and alert_ids:
        placeholders = ",".join("?" for _ in alert_ids)
        rows = DB.execute(
            f"SELECT * FROM recommendations WHERE alert_id IN ({placeholders}) ORDER BY created_at ASC",
            tuple(alert_ids),
        ).fetchall()
    items = []
    for r in rows:
        decisions = DB.execute(
            "SELECT * FROM approval_decisions WHERE recommendation_id=? ORDER BY id ASC",
            (r["id"],),
        ).fetchall()
        items.append(
            {
                **r,
                "args": json.loads(r["args"] or "{}"),
                "decisions": decisions,
            }
        )
    return {"incident_id": real_inc_id, "recommendations": items, "count": len(items)}


@v1_router.post("/recommendations/{recommendation_id}/decision")
async def decide_recommendation(
    recommendation_id: str,
    req: RecommendationDecisionRequest,
) -> dict[str, Any]:
    try:
        res = await resolve_approval_decision(
            key=recommendation_id,
            decision=req.decision,
            analyst_id=req.analyst_id,
            comment=req.comment,
        )
        return {"ok": True, **res}
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"Recommendation '{recommendation_id}' not found or already resolved",
        )


@v1_router.get("/audit-logs")
def get_v1_audit_logs(
    alert_id: str | None = Query(default=None),
    agent: str | None = Query(default=None),
) -> dict[str, Any]:
    all_rows = DB.execute("SELECT * FROM audit ORDER BY n ASC").fetchall()
    chain_valid = _verify_audit_chain(all_rows)

    filtered = all_rows
    if alert_id:
        filtered = [r for r in filtered if r["alert_id"] == alert_id]
    if agent:
        filtered = [r for r in filtered if r["agent"] == agent]

    items = [{**r, "data": json.loads(r["data"] or "{}")} for r in filtered]
    return {
        "chain_valid": chain_valid,
        "total_chain_length": len(all_rows),
        "count": len(items),
        "items": items,
    }
