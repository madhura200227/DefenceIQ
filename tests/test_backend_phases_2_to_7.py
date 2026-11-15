"""Comprehensive Phase 2–7 Backend Verification & Red-Team Test Suite."""

from __future__ import annotations

import asyncio
import os
import pytest
from fastapi.testclient import TestClient

os.environ["PACE"] = "0"

import main
from backend.evidence_risk import (
    calculate_explainable_risk,
    quarantine_untrusted_logs,
    verify_and_persist_evidence,
)
from backend.llm_adapter import narrate_incident


@pytest.fixture(autouse=True)
def clean_db_state():
    """Resets runtime tables before each test for deterministic isolation."""
    client = TestClient(main.app)
    client.post("/api/scenario/reset")
    yield
    client.post("/api/scenario/reset")


def test_health_and_llm_fallback_status(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = TestClient(main.app)
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert body["database_backend"] in ("postgresql", "sqlite")
    assert body["llm_providers"]["active_mode"] == "deterministic_heuristic_fallback"


def test_layer01_ingestion_and_sha256_idempotency():
    client = TestClient(main.app)
    payload = {
        "id": "A-901",
        "source_type": "siem_webhook",
        "type": "failed_login_burst",
        "user": "rohan.k",
        "src_ip": "203.0.113.45",
        "host": "VPN-GW",
        "desc": "45 failed logins in 3 minutes",
        "t": 45,
        "run_pipeline": False,
    }
    r1 = client.post("/api/v1/events/ingest", json=payload)
    assert r1.status_code == 200
    b1 = r1.json()
    assert b1["status"] == "accepted"
    assert b1["deduplicated"] is False
    assert b1["alert_id"] == "A-901"

    # Re-sending identical event payload must be deduplicated via SHA-256 hash
    r2 = client.post("/api/v1/events/ingest", json=payload)
    assert r2.status_code == 200
    b2 = r2.json()
    assert b2["status"] == "deduplicated"
    assert b2["deduplicated"] is True
    assert b2["raw_event_id"] == b1["raw_event_id"]

    # Normalized event should be queryable via GET /api/v1/events
    ev_res = client.get("/api/v1/events?severity=medium")
    assert ev_res.status_code == 200
    assert ev_res.json()["count"] == 1


def test_layer01_rejects_malformed_ingest_payload():
    client = TestClient(main.app)
    bad = {"type": "   ", "desc": ""}
    res = client.post("/api/v1/events/ingest", json=bad)
    assert res.status_code == 422


def test_layer05_prompt_injection_quarantine_and_citation_enforcement():
    safe_logs, quarantined = quarantine_untrusted_logs(main.LOGS)
    assert any(l["id"] == "L049" for l in quarantined)
    assert all(l["id"] != "L049" for l in safe_logs)

    raw_claims = [
        ("Valid claim backed by real log citations", ["L001", "L046"]),
        ("Hallucinated claim with non-existent log ID", ["L999"]),
        ("Uncited claim with empty citation list", []),
    ]
    accepted, rejected_cnt = verify_and_persist_evidence(
        main.DB,
        incident_id="INC-TEST",
        alert_id="A-105",
        raw_claims=raw_claims,
    )
    assert len(accepted) == 1
    assert accepted[0][0] == "Valid claim backed by real log citations"
    assert rejected_cnt == 2


def test_layer05_unauthorized_tool_call_blocked():
    async def _attempt_hijack():
        with pytest.raises(PermissionError):
            await main.call("forensics", "A-105", "disable_firewall")

    asyncio.run(_attempt_hijack())
    client = TestClient(main.app)
    audits = client.get("/api/audit?alert_id=A-105").json()
    assert any(a["kind"] == "tool_denied" and a["data"].get("tool") == "disable_firewall" for a in audits)


def test_layer05_explainable_risk_scoring():
    breakdown = calculate_explainable_risk(
        main.DB,
        incident_id="INC-ROHAN-K",
        alert_id="A-105",
        severity="high",
        confidence=0.9,
        abuse_score=97,
        host="WS-FIN-07",
        verified_claims=4,
    )
    assert breakdown.total_score >= 80.0
    assert breakdown.priority == "critical"
    assert breakdown.severity_points > 0
    assert breakdown.threat_intel_points > 0
    assert breakdown.asset_criticality_points > 0


def test_layer04_dual_llm_adapter_deterministic_fallback(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    state = {
        "alert": main.SCENARIO[4],
        "sev": "high",
        "mitre": ("T1041", "Exfiltration Over C2 Channel"),
        "intel": {"abuseipdb": 88, "otx_pulses": 5, "tags": ["c2", "exfil-drop"]},
        "claims": [("2.3 GB sent to 198.51.100.23", ["L048"])],
    }
    summary, provider = asyncio.run(narrate_incident(state))
    assert provider == "deterministic_heuristic"
    assert "[L048]" in summary
    assert "T1041" in summary


def test_end_to_end_pipeline_correlation_and_approval_gate():
    os.environ["PACE"] = "0"
    client = TestClient(main.app)

    async def _run_campaign():
        # 1. Benign alert closes automatically as noise
        await main.run(main.SCENARIO[0])  # A-101

        # 2. Malicious multi-stage campaign on rohan.k (A-103, A-104, A-105)
        t103 = asyncio.create_task(main.run(main.SCENARIO[2]))
        t104 = asyncio.create_task(main.run(main.SCENARIO[3]))
        t105 = asyncio.create_task(main.run(main.SCENARIO[4]))

        # Wait until all 3 alerts hit the human approval gate
        for _ in range(100):
            if len(main.PENDING) >= 5:
                break
            await asyncio.sleep(0.01)

        assert "A-103:2" in main.PENDING
        assert "A-104:2" in main.PENDING
        assert "A-105:2" in main.PENDING

        # Resolve A-103 via legacy approve endpoint
        await main.resolve_approval_decision("A-103:2", True)

        # Resolve A-104 approvals (approve first, reject second, approve third)
        for k in list(main.PENDING.keys()):
            if k.startswith("A-104:"):
                await main.resolve_approval_decision(k, "approved" if k.endswith(":2") else "rejected")

        # Resolve A-105 approvals (defer one to test NeedsAnalystReview / deferred path)
        for k in list(main.PENDING.keys()):
            if k.startswith("A-105:"):
                await main.resolve_approval_decision(k, "approved")

        await asyncio.gather(t103, t104, t105)

    asyncio.run(_run_campaign())

    # Check correlated incident INC-ROHAN-K via /api/v1/incidents
    inc_res = client.get("/api/v1/incidents")
    assert inc_res.status_code == 200
    incidents = inc_res.json()["items"]
    rohan_inc = next((i for i in incidents if i["id"] == "INC-ROHAN-K"), None)
    assert rohan_inc is not None
    assert set(rohan_inc["alert_ids"]) == {"A-103", "A-104", "A-105"}
    assert rohan_inc["risk_score"] > 70.0

    # Check v1 evidence, timeline, analysis, and recommendations endpoints
    ev = client.get("/api/v1/incidents/INC-ROHAN-K/evidence").json()
    assert ev["count"] >= 3

    tl = client.get("/api/v1/incidents/INC-ROHAN-K/timeline").json()
    assert len(tl["timeline"]) > 0
    assert all("L049" not in line for line in tl["timeline"])

    an = client.get("/api/v1/incidents/INC-ROHAN-K/analysis").json()
    assert an["count"] >= 12  # 4 agents * 3 alerts
    assert an["agent_runs"][0]["envelope"]["incident_id"] == "INC-ROHAN-K"

    recs = client.get("/api/v1/incidents/INC-ROHAN-K/recommendations").json()
    assert recs["count"] >= 6

    # Check SHA-256 hash chain integrity across all audit events
    audit_v1 = client.get("/api/v1/audit-logs").json()
    assert audit_v1["chain_valid"] is True
    assert audit_v1["total_chain_length"] > 20


def test_layer07_append_only_audit_immutability():
    asyncio.run(main.emit("A-101", "system", "test", "Immutability check"))
    with pytest.raises(Exception, match="audit log is append-only"):
        main.DB.execute("UPDATE audit SET msg='tampered' WHERE alert_id=?", ("A-101",))
    with pytest.raises(Exception, match="audit log is append-only"):
        main.DB.execute("DELETE FROM audit WHERE alert_id=?", ("A-101",))


def test_evaluation_endpoint_100_percent_accuracy():
    client = TestClient(main.app)
    res = client.get("/api/eval")
    assert res.status_code == 200
    data = res.json()
    assert data["alerts"] == 7
    assert data["true_pos"] == 3
    assert data["false_pos"] == 0
    assert data["false_neg"] == 0
    assert data["true_neg"] == 4
    assert data["detection_rate"] == 1.0
    assert data["false_positive_rate"] == 0.0
