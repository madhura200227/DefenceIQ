"""DefenceIQ Layers 04-07 — Multi-Agent State Graph, Tool Guardrails, Approval Gate & Audit Stream."""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

from backend.database import DatabaseAdapter, compute_audit_hash
from backend.datasets import KNOWN_GOOD, LOGS, SCENARIO, TRAVELERS
from backend.evidence_risk import (
    INJECTION,
    calculate_explainable_risk,
    verify_and_persist_evidence,
)
from backend.ingestion import ingest_raw_event
from backend.intel import enrich_ip_indicator, lookup_ip_local, map_mitre_technique
from backend.llm_adapter import narrate_incident, record_agent_run
from backend.normalization import correlate_alert_to_incident, normalize_and_extract

# Shared primary database adapter instance
DB = DatabaseAdapter()

# ---------- allow-listed tools: the only things an agent can ever do ----------
SIM = lambda **k: f"simulated: {k}"
TOOLS: dict[str, Any] = {
    "query_history": lambda user: {"travels_often": user in TRAVELERS},
    "lookup_ip": lookup_ip_local,
    "mitre_map": map_mitre_technique,
    "query_logs": lambda ip="", host="", until=999: [
        l
        for l in LOGS
        if l["t"] <= until and ((ip and l["ip"] == ip) or (host and l["host"] == host))
    ],
    **{
        n: SIM
        for n in (
            "tag_alert",
            "add_comment",
            "disable_account",
            "force_password_reset",
            "block_ip",
            "isolate_host",
        )
    },
}

ALLOW: dict[str, set[str]] = {
    "triage": {"query_history"},
    "intel": {"lookup_ip", "mitre_map"},
    "forensics": {"query_logs"},
    "response": {
        "tag_alert",
        "add_comment",
        "disable_account",
        "force_password_reset",
        "block_ip",
        "isolate_host",
    },
}
LOW_RISK: set[str] = {"tag_alert", "add_comment"}

# ---------- audit log + live streaming ----------
CLIENTS: set[Any] = set()
PENDING: dict[str, asyncio.Future[Any]] = {}
_LAST_HASH: str = "GENESIS"


async def emit(aid: str, agent: str, kind: str, msg: str, **data: Any) -> dict[str, Any]:
    global _LAST_HASH
    ts = time.time()
    data_json = json.dumps(data, sort_keys=True)
    prev_hash = _LAST_HASH
    row_hash = compute_audit_hash(prev_hash, ts, aid, agent, kind, msg, data_json)
    _LAST_HASH = row_hash

    DB.execute(
        "INSERT INTO audit(ts,alert_id,agent,kind,msg,data,prev_hash,row_hash) VALUES(?,?,?,?,?,?,?,?)",
        (ts, aid, agent, kind, msg, data_json, prev_hash, row_hash),
    )
    DB.commit()

    ev = dict(ts=ts, alert_id=aid, agent=agent, kind=kind, msg=msg, data=data)
    for ws in list(CLIENTS):
        try:
            await ws.send_json(ev)
        except Exception:
            CLIENTS.discard(ws)

    pace = float(os.getenv("PACE", "0.6"))
    if pace > 0:
        await asyncio.sleep(pace)
    return ev


async def call(agent: str, aid: str, name: str, **kw: Any) -> Any:
    if name not in ALLOW.get(agent, set()):
        await emit(
            aid,
            agent,
            "tool_denied",
            f"BLOCKED: {agent} is not allowed to call {name}",
            tool=name,
        )
        raise PermissionError(name)
    out = TOOLS[name](**kw)
    shown = out if len(str(out)) < 300 else f"[{len(out)} items]"
    await emit(
        aid,
        agent,
        "tool_call",
        f"{name}({', '.join(f'{k}={v}' for k, v in kw.items())})",
        tool=name,
        args=kw,
        result=shown,
    )
    return out


def setstatus(aid: str, status: str, report: str | None = None) -> None:
    DB.execute(
        "UPDATE alerts SET status=?, report=COALESCE(?,report) WHERE id=?",
        (status, report, aid),
    )
    row = DB.execute("SELECT incident_id FROM alerts WHERE id=?", (aid,)).fetchone()
    if row and row.get("incident_id"):
        DB.execute(
            "UPDATE incidents SET status=?, updated_at=? WHERE id=?",
            (status, time.time(), row["incident_id"]),
        )
    DB.commit()


# ---------- agents (graph nodes) ----------
def triage_logic(a: dict[str, Any], h: dict[str, Any]) -> tuple[bool, float, str, str]:
    if a.get("src_ip") in KNOWN_GOOD:
        return False, 0.05, "low", f"Source is the {KNOWN_GOOD[a['src_ip']]}"
    base = {
        "failed_login_burst": 0.7,
        "bruteforce_then_success": 0.9,
        "impossible_travel": 0.75,
        "large_outbound_transfer": 0.8,
    }.get(a.get("type", ""), 0.1)
    why = "Matches a known attack pattern" if base >= 0.5 else "Low-signal alert, no known attack pattern"
    if a.get("type") == "impossible_travel" and h.get("travels_often"):
        base, why = base - 0.4, "User travels often; likely benign"
    sev = "high" if base >= 0.8 else "medium" if base >= 0.5 else "low"
    return base >= 0.5, base, sev, why


async def triage(s: dict[str, Any]) -> None:
    t0 = time.perf_counter()
    a = s["alert"]
    aid = a["id"]
    await emit(aid, "triage", "start", "Assessing: " + a["desc"])
    h = await call("triage", aid, "query_history", user=a.get("user", ""))
    esc, conf, sev, why = triage_logic(a, h)
    s.update(escalate=esc, sev=sev, conf=conf, why=why)
    DB.execute("UPDATE alerts SET severity=?, confidence=? WHERE id=?", (sev, conf, aid))
    DB.commit()

    incident_id = correlate_alert_to_incident(DB, a, esc, sev)
    s["incident_id"] = incident_id or f"INC-{aid}"
    setstatus(aid, "investigating" if esc else "closed_noise")

    verdict_msg = f"{'ESCALATE' if esc else 'CLOSE'} severity={sev} confidence={conf:.2f}. {why}"
    await emit(aid, "triage", "verdict", verdict_msg)

    record_agent_run(
        DB,
        incident_id=s["incident_id"],
        alert_id=aid,
        agent_type="triage",
        summary=verdict_msg,
        findings=[(why, [aid])],
        confidence_label=sev,  # type: ignore[arg-type]
        recommended_next_step="Enrich indicators with Threat Intel" if esc else "Close alert as noise",
        duration_ms=(time.perf_counter() - t0) * 1000,
    )


async def intel(s: dict[str, Any]) -> None:
    t0 = time.perf_counter()
    a = s["alert"]
    aid = a["id"]
    ip = await call("intel", aid, "lookup_ip", ip=a.get("src_ip", ""))
    # Also persist enrichment record in intelligence_records
    await enrich_ip_indicator(DB, a.get("src_ip", ""), a.get("type", ""))
    tid, tname = await call("intel", aid, "mitre_map", atype=a.get("type", ""))
    s.update(intel=ip, mitre=(tid, tname))

    verdict_msg = (
        f"IP reputation {ip['abuseipdb']}/100, {ip['otx_pulses']} OTX pulses, "
        f"tags {ip['tags']}. MITRE {tid} {tname}"
    )
    await emit(aid, "intel", "verdict", verdict_msg)

    record_agent_run(
        DB,
        incident_id=s.get("incident_id", f"INC-{aid}"),
        alert_id=aid,
        agent_type="threat_analysis",
        summary=verdict_msg,
        findings=[(f"Source IP {a.get('src_ip')} AbuseIPDB={ip['abuseipdb']}/100 ({tid} {tname})", [aid])],
        confidence_label="high" if ip["abuseipdb"] >= 80 else "medium",
        recommended_next_step="Query host and authentication logs for forensic timeline",
        duration_ms=(time.perf_counter() - t0) * 1000,
    )


async def forensics(s: dict[str, Any]) -> None:
    t0 = time.perf_counter()
    a = s["alert"]
    aid = a["id"]
    lines = await call(
        "forensics",
        aid,
        "query_logs",
        ip=a.get("src_ip", ""),
        host=a.get("host", ""),
        until=a.get("t", 999),
    )
    safe = []
    for l in lines:
        if INJECTION.search(l["msg"]):
            await emit(
                aid,
                "forensics",
                "injection_quarantined",
                f"Prompt injection in {l['id']} quarantined, excluded from evidence",
            )
            await emit(
                aid,
                "forensics",
                "red_team",
                "Red-team check: simulating a hijacked agent trying to call disable_firewall",
            )
            try:
                await call("forensics", aid, "disable_firewall")
            except PermissionError:
                pass
        else:
            safe.append(l)

    safe.sort(key=lambda l: l["t"])
    F = lambda e: [l for l in safe if l["event"] == e]
    fails, oks, xfer = F("login_failed"), F("login_ok"), F("data_transfer")
    raw: list[tuple[str, list[str]]] = []
    if fails:
        raw.append((f"{len(fails)} failed logins from {a['src_ip']}", [fails[0]["id"], fails[-1]["id"]]))
    if fails and oks:
        raw.append(("Successful login after repeated failures (likely credential compromise)", [oks[0]["id"]]))
    raw += [(l["msg"], [l["id"]]) for l in F("host_access") + xfer]

    good, rejected_cnt = verify_and_persist_evidence(
        DB,
        incident_id=s.get("incident_id", f"INC-{aid}"),
        alert_id=aid,
        raw_claims=raw,
    )
    s.update(claims=good, compromised=bool(fails and oks), xfer=bool(xfer))

    await emit(
        aid,
        "forensics",
        "citation_check",
        f"{len(good)} claims accepted, {rejected_cnt} rejected for missing citations",
    )
    timeline_entries = [f"{l['id']} t+{l['t']}m {l['event']}: {l['msg']}" for l in safe]
    await emit(
        aid,
        "forensics",
        "timeline",
        f"Timeline built from {len(safe)} log lines",
        timeline=timeline_entries,
    )

    # Calculate explainable composite risk score (Layer 05)
    risk = calculate_explainable_risk(
        DB,
        incident_id=s.get("incident_id", f"INC-{aid}"),
        alert_id=aid,
        severity=s.get("sev", "medium"),
        confidence=float(s.get("conf", 0.7)),
        abuse_score=int(s.get("intel", {}).get("abuseipdb", 0)),
        host=a.get("host", ""),
        verified_claims=len(good),
    )
    s["risk"] = risk

    record_agent_run(
        DB,
        incident_id=s.get("incident_id", f"INC-{aid}"),
        alert_id=aid,
        agent_type="evidence_analysis",
        summary=f"Validated {len(good)} claims across {len(safe)} safe log lines. {risk.rationale}",
        findings=good,
        confidence_label="high" if good else "low",
        recommended_next_step="Formulate proportionate response actions",
        duration_ms=(time.perf_counter() - t0) * 1000,
    )


async def response(s: dict[str, Any]) -> None:
    t0 = time.perf_counter()
    a = s["alert"]
    aid = a["id"]
    acts: list[tuple[str, dict[str, Any]]] = [
        ("tag_alert", {"tag": s["mitre"][0]}),
        ("add_comment", {"text": "DefenceIQ: " + a["desc"]}),
    ]
    if s["intel"]["abuseipdb"] >= 50:
        acts.append(("block_ip", {"ip": a["src_ip"]}))
    if s["compromised"]:
        acts += [
            ("disable_account", {"user": a["user"]}),
            ("force_password_reset", {"user": a["user"]}),
        ]
    if s["xfer"]:
        acts.append(("isolate_host", {"host": a["host"]}))

    s["actions"] = acts
    proposal_msg = "Proposed: " + ", ".join(n for n, _ in acts)
    await emit(aid, "response", "proposal", proposal_msg)

    record_agent_run(
        DB,
        incident_id=s.get("incident_id", f"INC-{aid}"),
        alert_id=aid,
        agent_type="remediation",
        summary=proposal_msg,
        findings=[(f"Proposed {name}({args})", [aid]) for name, args in acts],
        confidence_label="high",
        recommended_next_step="Route high-risk containment actions through Human Approval Gate",
        duration_ms=(time.perf_counter() - t0) * 1000,
    )


async def gate(s: dict[str, Any]) -> None:
    aid = s["alert"]["id"]
    incident_id = s.get("incident_id", f"INC-{aid}")
    waits: list[tuple[str, str, dict[str, Any], asyncio.Future[Any]]] = []
    now = time.time()

    for i, (name, args) in enumerate(s["actions"]):
        key = f"{aid}:{i}"
        is_low = name in LOW_RISK
        risk_lvl = "low" if is_low else "high"
        status_init = "auto_approved" if is_low else "awaiting_approval"

        DB.execute(
            """INSERT OR IGNORE INTO recommendations(
                id,incident_id,alert_id,action_type,args,rationale,risk_level,approval_status,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                key,
                incident_id,
                aid,
                name,
                json.dumps(args),
                f"Proposed by Response Planner for {aid}",
                risk_lvl,
                status_init,
                now,
            ),
        )
        DB.commit()

        if is_low:
            await call("response", aid, name, **args)
            s["outcomes"].append(f"auto-run: {name} {args}")
            continue

        fut = asyncio.get_running_loop().create_future()
        PENDING[key] = fut
        await emit(
            aid,
            "gate",
            "approval_required",
            f"{name} {args} needs analyst approval",
            key=key,
            action=name,
            args=args,
        )
        waits.append((key, name, args, fut))

    if waits:
        setstatus(aid, "awaiting_approval")

    for key, name, args, fut in waits:
        decision_val = await fut
        if decision_val is True or decision_val == "approved":
            out_res = await call("response", aid, name, **args)
            s["outcomes"].append(f"approved and run: {name} {args}")
            DB.execute("UPDATE recommendations SET approval_status='approved' WHERE id=?", (key,))
            DB.execute(
                "UPDATE approval_decisions SET execution_result=? WHERE recommendation_id=?",
                (str(out_res), key),
            )
            DB.commit()
        elif decision_val == "deferred":
            await emit(aid, "gate", "deferred", f"{name} deferred for further analyst review", key=key)
            s["outcomes"].append(f"deferred: {name} {args}")
            DB.execute("UPDATE recommendations SET approval_status='deferred' WHERE id=?", (key,))
            DB.commit()
        else:
            await emit(aid, "gate", "rejected", f"{name} rejected, not executed")
            s["outcomes"].append(f"rejected: {name} {args}")
            DB.execute("UPDATE recommendations SET approval_status='rejected' WHERE id=?", (key,))
            DB.commit()


async def resolve_approval_decision(
    key: str,
    decision: str | bool = True,
    analyst_id: str = "soc.analyst@defenceiq.local",
    comment: str = "",
) -> dict[str, Any]:
    """Resolves a pending approval gate both in-memory (Future) and in the persistent DB."""
    if isinstance(decision, bool):
        norm_decision = "approved" if decision else "rejected"
        bool_val: Any = decision
    else:
        norm_decision = decision
        bool_val = True if decision == "approved" else ("deferred" if decision == "deferred" else False)

    fut = PENDING.pop(key, None)
    rec = DB.execute("SELECT * FROM recommendations WHERE id=?", (key,)).fetchone()
    if not fut and not rec:
        raise KeyError(key)

    aid = key.split(":")[0]
    kind = (
        "approved"
        if norm_decision == "approved"
        else "deferred_by_analyst"
        if norm_decision == "deferred"
        else "rejected_by_analyst"
    )
    await emit(
        aid,
        "analyst",
        kind,
        f"Analyst {norm_decision} {key}" + (f" ({comment})" if comment else ""),
        key=key,
        analyst_id=analyst_id,
        decision=norm_decision,
    )

    now = time.time()
    DB.execute(
        """INSERT INTO approval_decisions(
            recommendation_id,analyst_id,decision,comment,execution_result,decided_at
        ) VALUES(?,?,?,?,?,?)""",
        (key, analyst_id, norm_decision, comment, "pending_execution" if norm_decision == "approved" else norm_decision, now),
    )
    DB.execute("UPDATE recommendations SET approval_status=? WHERE id=?", (norm_decision, key))
    DB.commit()

    if fut and not fut.done():
        fut.set_result(bool_val)
    elif rec:
        # Handle DB-persisted recommendation when server restarted and in-memory Future was lost
        args = json.loads(rec["args"] or "{}")
        if norm_decision == "approved":
            out_res = await call("response", aid, rec["action_type"], **args)
            DB.execute(
                "UPDATE approval_decisions SET execution_result=? WHERE recommendation_id=?",
                (str(out_res), key),
            )
            DB.commit()
        rem = DB.execute(
            "SELECT COUNT(*) AS cnt FROM recommendations WHERE alert_id=? AND approval_status='awaiting_approval'",
            (aid,),
        ).fetchone()
        if rem and int(rem.get("cnt") or 0) == 0:
            setstatus(aid, "resolved")

    return {"key": key, "alert_id": aid, "decision": norm_decision, "analyst_id": analyst_id}


NODES = {
    "triage": triage,
    "intel": intel,
    "forensics": forensics,
    "response": response,
    "gate": gate,
}
EDGES = {
    "triage": lambda s: "intel" if s["escalate"] else None,
    "intel": lambda s: "forensics",
    "forensics": lambda s: "response",
    "response": lambda s: "gate",
    "gate": lambda s: None,
}


async def narrate(s: dict[str, Any]) -> str:
    text, _provider = await narrate_incident(s)
    return text


async def build_report(s: dict[str, Any]) -> str:
    a = s["alert"]
    ev = "\n".join(f"- {t} [{', '.join(c)}]" for t, c in s["claims"])
    out = "\n".join(f"- {o}" for o in s["outcomes"])
    risk_info = ""
    if "risk" in s:
        risk_info = f" | Risk Score {s['risk'].total_score}/100 ({s['risk'].priority})"
    return (
        f"Incident {a['id']}: {a['desc']}\n"
        f"Severity {s['sev']} | MITRE {s['mitre'][0]} {s['mitre'][1]}{risk_info}\n\n"
        f"Summary\n{await narrate(s)}\n\n"
        f"Evidence (cited log lines)\n{ev}\n\n"
        f"Actions\n{out}"
    )


async def run(a: dict[str, Any]) -> None:
    aid = a["id"]
    now = time.time()
    ingested = ingest_raw_event(DB, a, source_type="scenario")
    normalize_and_extract(DB, ingested["raw_event_id"], a)

    DB.execute(
        "INSERT OR REPLACE INTO alerts(id,raw,status,created_at) VALUES(?,?,'new',?)",
        (aid, json.dumps(a), now),
    )
    DB.commit()

    await emit(aid, "ingest", "alert_received", f"{a['desc']} (ip={a['src_ip']})")
    s: dict[str, Any] = {"alert": a, "escalate": False, "outcomes": []}
    node: str | None = "triage"
    while node:
        await NODES[node](s)
        node = EDGES[node](s)

    report = await build_report(s) if s["escalate"] else f"Closed as noise by triage. {s['why']}"
    final_status = (
        "NeedsAnalystReview"
        if any(o.startswith("deferred:") for o in s["outcomes"])
        else ("resolved" if s["escalate"] else "closed_noise")
    )
    setstatus(aid, "resolved" if final_status == "NeedsAnalystReview" else final_status, report)
    await emit(aid, "system", "done", "Incident finished")


async def run_all() -> None:
    for a in SCENARIO:
        asyncio.create_task(run(a))
        await asyncio.sleep(0.3)

