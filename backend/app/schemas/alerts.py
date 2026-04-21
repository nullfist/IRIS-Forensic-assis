from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import Field

from backend.app.models.enums import AlertStatus, AttackPhase, SeverityLevel
from backend.app.schemas.base import IRISBaseModel


class AlertEvidence(IRISBaseModel):
    event_id: str | None = None
    entity_id: str | None = None
    summary: str
    confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    details: dict[str, Any] = Field(default_factory=dict)


class Alert(IRISBaseModel):
    alert_id: str
    investigation_id: str
    family: str
    title: str
    summary: str
    description: str = ""  # frontend alias for summary
    severity: SeverityLevel
    phase: AttackPhase
    status: AlertStatus = AlertStatus.NEW
    confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    host: str | None = None
    user: str | None = None
    source_event_ids: list[str] = Field(default_factory=list)
    evidence: list[AlertEvidence] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def model_post_init(self, __context: object) -> None:
        if not self.description:
            self.description = self.summary


class AlertFilters(IRISBaseModel):
    investigation_id: str | None = None
    severity: SeverityLevel | None = None
    phase: AttackPhase | None = None
    status: AlertStatus | None = None
    host: str | None = None
    user: str | None = None


class AlertListResponse(IRISBaseModel):
    items: list[Alert]
    total: int


class ReasoningStep(IRISBaseModel):
    title: str
    detail: str
    supporting_event_ids: list[str] = Field(default_factory=list)


class ExplanationResponse(IRISBaseModel):
    alert_id: str
    summary: str
    reasoning_chain: list[ReasoningStep]
    attack_tactics: list[str]
    confidence_summary: str
    confidence_explanation: str = ""  # alias for frontend compatibility
    next_steps: list[str]

    def model_post_init(self, __context: object) -> None:
        if not self.confidence_explanation:
            self.confidence_explanation = self.confidence_summary