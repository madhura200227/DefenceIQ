"""DefenceIQ Enterprise Multi-Agent Threat Intelligence & Incident Response Platform.

Root ASGI entrypoint exposing:
- Legacy endpoints (/api/scenario/run, /api/scenario/reset, /api/alerts, /api/audit, /api/approve/{key}, /api/eval, /ws)
- Enterprise REST API v1 (/api/v1/*)
- Re-exported symbols for backward compatibility with existing tests and scripts.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from backend.api_v1 import v1_router
from backend.datasets import (
    A,
    KNOWN_BAD,
    KNOWN_GOOD,
    L,
    LOGS,
    MITRE,
    SCENARIO,
    TRAVELERS,
)
from backend.evidence_risk import INJECTION
import backend.orchestrator as _orch
from backend.orchestrator import (
    ALLOW,
    CLIENTS,
    DB,
    EDGES,
    LOW_RISK,
    NODES,
    PENDING,
    SIM,
    TOOLS,
    build_report,
    call,
    emit,
    forensics,
    gate,
    intel,
    narrate,
    resolve_approval_decision,
    response,
    run,
    run_all,
    setstatus,
    triage,
    triage_logic,
)

# ---------- CORS & Origin Guard ----------
DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://defenceiq-theta.vercel.app",
    "https://defenceiq-5iazzx3nb-madhura-lakade-s-projects.vercel.app",
]
env_origins = [
    o.strip()
    for o in os.getenv("DEFENCEIQ_ALLOWED_ORIGINS", "").split(",")
    if o.strip()
]
ALLOWED_ORIGINS = env_origins if env_origins else DEFAULT_ALLOWED_ORIGINS

app = FastAPI(
    title="DefenceIQ",
    version="1.0.0",
    description="AI-Powered Multi-Agent Threat Intelligence & Incident Response Platform",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(v1_router)


def is_allowed_origin(origin: str | None) -> bool:
    if not origin:
        return True
    return origin.rstrip("/") in {o.rstrip("/") for o in ALLOWED_ORIGINS}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(os.path.join(os.path.dirname(__file__), "index.html"))


@app.post("/api/scenario/run")
async def start() -> dict[str, Any]:
    if DB.execute("SELECT 1 FROM alerts").fetchone():
        raise HTTPException(
            409,
            "Scenario already ran. Call POST /api/scenario/reset or restart the server to replay it.",
        )
    asyncio.create_task(run_all())
    return {"started": len(SCENARIO)}


@app.post("/api/scenario/reset")
async def reset_scenario() -> dict[str, Any]:
    for fut in list(PENDING.values()):
        if not fut.done():
            fut.cancel()
    PENDING.clear()
    _orch._LAST_HASH = "GENESIS"
    DB.reset_runtime_tables()
    return {"reset": True, "status": "clean"}


@app.get("/api/alerts")
def alerts() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in DB.execute("SELECT * FROM alerts ORDER BY created_at ASC, id ASC").fetchall():
        d = dict(r)
        raw = json.loads(d.pop("raw"))
        out.append({**d, **{k: v for k, v in raw.items() if k != "label"}})
    return out


@app.get("/api/audit")
def audit(alert_id: str = "") -> list[dict[str, Any]]:
    q = (
        "SELECT * FROM audit"
        + (" WHERE alert_id=?" if alert_id else "")
        + " ORDER BY id ASC"
    )
    rows = DB.execute(q, (alert_id,) if alert_id else ()).fetchall()
    return [
        {**r, "n": r["id"], "data": json.loads(r["data"] or "{}")}
        for r in rows
    ]


@app.post("/api/approve/{key}")
async def approve(key: str, ok: bool = True) -> dict[str, Any]:
    try:
        return await resolve_approval_decision(key=key, decision=ok)
    except KeyError:
        raise HTTPException(404, "No such pending approval")


@app.get("/api/eval")
def evaluate() -> dict[str, Any]:
    tp = fp = tn = fn = 0
    t0 = time.perf_counter()
    for a in SCENARIO:
        esc = triage_logic(a, TOOLS["query_history"](user=a["user"]))[0]
        mal = a["label"] == "malicious"
        tp += int(esc and mal)
        fp += int(esc and not mal)
        fn += int((not esc) and mal)
        tn += int((not esc) and not mal)
    return dict(
        alerts=len(SCENARIO),
        true_pos=tp,
        false_pos=fp,
        false_neg=fn,
        true_neg=tn,
        detection_rate=tp / max(tp + fn, 1),
        false_positive_rate=fp / max(fp + tn, 1),
        avg_triage_ms=round((time.perf_counter() - t0) * 1000 / len(SCENARIO), 3),
        manual_baseline_min_per_alert=15,
        note="7 hand-labelled scenario alerts and an assumed manual baseline: demo numbers, not a benchmark",
    )


@app.websocket("/ws")
async def ws(w: WebSocket) -> None:
    origin = w.headers.get("origin")
    if not is_allowed_origin(origin):
        await w.close(code=1008)
        return
    await w.accept()
    CLIENTS.add(w)
    try:
        while True:
            await w.receive_text()
    except WebSocketDisconnect:
        CLIENTS.discard(w)


__all__ = [
    "A",
    "ALLOW",
    "ALLOWED_ORIGINS",
    "CLIENTS",
    "DB",
    "EDGES",
    "INJECTION",
    "KNOWN_BAD",
    "KNOWN_GOOD",
    "L",
    "LOGS",
    "LOW_RISK",
    "MITRE",
    "NODES",
    "PENDING",
    "SCENARIO",
    "SIM",
    "TOOLS",
    "TRAVELERS",
    "app",
    "build_report",
    "call",
    "emit",
    "forensics",
    "gate",
    "intel",
    "is_allowed_origin",
    "narrate",
    "resolve_approval_decision",
    "response",
    "run",
    "run_all",
    "setstatus",
    "triage",
    "triage_logic",
]
