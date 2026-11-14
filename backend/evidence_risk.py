"""DefenceIQ Layer 05 — Prompt-Injection Quarantine, Evidence Citation Verifier & Explainable Risk Engine."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from backend.database import DatabaseAdapter
from backend.datasets import ASSET_CRITICALITY, LOGS
from backend.schemas import RiskScoreBreakdown

INJECTION = re.compile(
    r"ignore (all )?(previous|prior)|system prompt|disable_\w+|you are now|override_policy",
    re.I,
)


def is_prompt_injection(text: str) -> bool:
    return bool(INJECTION.search(text or ""))


def verify_and_persist_evidence(
    db: DatabaseAdapter,
    *,
    incident_id: str,
    alert_id: str,
    raw_claims: list[tuple[str, list[str]]],
    valid_log_ids: set[str] | None = None,
) -> tuple[list[tuple[str, list[str]]], int]:
    """Enforces strict log citation verification and persists records in `evidence`.

    Returns (accepted_claims, rejected_count).
    """
    known_ids = valid_log_ids if valid_log_ids is not None else {l["id"] for l in LOGS}
    accepted: list[tuple[str, list[str]]] = []
    rejected = 0
    now = time.time()

    for claim_text, refs in raw_claims:
        is_valid = bool(refs) and all(ref in known_ids for ref in refs)
        if is_valid:
            accepted.append((claim_text, refs))
        else:
            rejected += 1

        db.execute(
            """INSERT INTO evidence(
                incident_id,alert_id,evidence_type,claim,source_refs,verified,created_at
            ) VALUES(?,?,?,?,?,?,?)""",
            (
                incident_id or f"INC-{alert_id}",
                alert_id,
                "direct_observation" if is_valid else "unverified_claim",
                claim_text,
                json.dumps(refs),
                1 if is_valid else 0,
                now,
            ),
        )
    db.commit()
    return accepted, rejected


def calculate_explainable_risk(
    db: DatabaseAdapter,
    *,
    incident_id: str,
    alert_id: str,
    severity: str,
    confidence: float,
    abuse_score: int,
    host: str,
    verified_claims: int,
) -> RiskScoreBreakdown:
    """Computes a documented, deterministic composite risk score in [0, 100].

    Weights:
    - Severity & triage confidence: up to 35 pts
    - Threat intelligence reputation: up to 25 pts
    - Correlated incident density: up to 15 pts
    - Asset criticality: up to 15 pts
    - Verified forensic evidence: up to 10 pts
    """
    sev_base = {"high": 35.0, "medium": 22.0, "low": 8.0}.get(severity, 8.0)
    sev_pts = round(sev_base * max(min(confidence, 1.0), 0.2), 2)
    ti_pts = round((max(min(abuse_score, 100), 0) / 100.0) * 25.0, 2)

    corr_count = 1
    if incident_id:
        rows = db.execute("SELECT COUNT(*) AS cnt FROM alerts WHERE incident_id=?", (incident_id,)).fetchall()
        if rows:
            corr_count = int(rows[0].get("cnt") or 1)
    corr_pts = round(min(corr_count * 5.0, 15.0), 2)

    asset_weight = ASSET_CRITICALITY.get(host, 0.6)
    asset_pts = round(asset_weight * 15.0, 2)
    ev_pts = round(min(verified_claims * 3.5, 10.0), 2)

    total = round(min(sev_pts + ti_pts + corr_pts + asset_pts + ev_pts, 100.0), 2)
    priority = (
        "critical" if total >= 80.0
        else "high" if total >= 60.0
        else "medium" if total >= 35.0
        else "low"
    )
    rationale = (
        f"Risk score {total}/100 ({priority}): severity={sev_pts}/35, threat_intel={ti_pts}/25, "
        f"correlation={corr_pts}/15 ({corr_count} alert(s)), asset={asset_pts}/15 ({host or 'unknown'}), "
        f"evidence={ev_pts}/10 ({verified_claims} cited claim(s))"
    )
    breakdown = RiskScoreBreakdown(
        total_score=total,
        priority=priority,  # type: ignore[arg-type]
        severity_points=sev_pts,
        threat_intel_points=ti_pts,
        correlation_points=corr_pts,
        asset_criticality_points=asset_pts,
        evidence_points=ev_pts,
        rationale=rationale,
    )

    db.execute("UPDATE alerts SET risk_score=? WHERE id=?", (total, alert_id))
    if incident_id:
        db.execute(
            "UPDATE incidents SET risk_score=?, priority=?, risk_breakdown=?, updated_at=? WHERE id=?",
            (total, priority, json.dumps(breakdown.model_dump()), time.time(), incident_id),
        )
    db.commit()
    return breakdown
