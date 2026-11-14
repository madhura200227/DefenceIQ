"""DefenceIQ Pydantic v2 Domain & API Contract Schemas."""

from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator


class IngestEventRequest(BaseModel):
    """Payload accepted by POST /api/v1/events/ingest."""

    id: str | None = None
    source_type: str = Field(default="json_webhook", min_length=1, max_length=64)
    type: str = Field(..., min_length=1, max_length=128)
    user: str = Field(default="", max_length=128)
    src_ip: str = Field(default="", max_length=64)
    host: str = Field(default="", max_length=128)
    desc: str = Field(..., min_length=1, max_length=1024)
    severity: Literal["low", "medium", "high"] | None = None
    t: int = Field(default=0, ge=0)
    run_pipeline: bool = Field(default=True)

    @field_validator("type", "desc")
    @classmethod
    def strip_non_empty(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Field cannot be empty or whitespace")
        return cleaned


class NormalizedEventSchema(BaseModel):
    id: str
    raw_event_id: str
    event_type: str
    severity: Literal["low", "medium", "high"]
    src_ip: str
    username: str
    hostname: str
    description: str
    scenario_offset: int
    occurred_at: float


class AgentFinding(BaseModel):
    finding: str = Field(..., min_length=1)
    evidence_refs: list[str] = Field(default_factory=list)
    confidence_label: Literal["low", "medium", "high"] = "medium"


class AgentOutputEnvelope(BaseModel):
    """Structured agent response envelope matching Architecture Section 8.2."""

    task_id: str
    incident_id: str
    agent_type: Literal["triage", "threat_analysis", "investigation", "evidence_analysis", "remediation"]
    status: Literal["completed", "degraded", "failed"] = "completed"
    summary: str
    findings: list[AgentFinding] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    recommended_next_step: str = "Proceed to next workflow stage"
    model_provider: str = "deterministic_heuristic"


class RiskScoreBreakdown(BaseModel):
    total_score: float = Field(..., ge=0.0, le=100.0)
    priority: Literal["low", "medium", "high", "critical"]
    severity_points: float
    threat_intel_points: float
    correlation_points: float
    asset_criticality_points: float
    evidence_points: float
    rationale: str


class RecommendationDecisionRequest(BaseModel):
    decision: Literal["approved", "rejected", "deferred"]
    analyst_id: str = Field(default="soc.analyst@defenceiq.local", min_length=1, max_length=128)
    comment: str = Field(default="", max_length=512)


class IncidentCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=256)
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    alert_ids: list[str] = Field(default_factory=list)
    rationale: str = Field(default="Manually created by analyst", max_length=512)
    metadata: dict[str, Any] = Field(default_factory=dict)
