from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import Field

from backend.app.models.enums import EventSource
from backend.app.schemas.base import IRISBaseModel


class IngestArtifact(IRISBaseModel):
    source: EventSource
    artifact_name: str = "unknown"
    content_type: str = "application/json"
    records: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IngestRequest(IRISBaseModel):
    investigation_id: str = Field(default="default-investigation")
    submitted_by: str | None = None
    artifacts: list[IngestArtifact]
    enrich_graph: bool = True


class IngestJobResponse(IRISBaseModel):
    job_id: str
    investigation_id: str = ""
    status: str
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    artifact_count: int
    message: str


class IngestJobStatusResponse(IRISBaseModel):
    job_id: str
    investigation_id: str
    status: str
    submitted_at: datetime
    completed_at: datetime | None = None
    processed_artifacts: int = 0
    normalized_events: int = 0
    generated_alerts: int = 0
    error: str | None = None


# ── Case Management ──────────────────────────────────────────────────

class CaseCreate(IRISBaseModel):
    name: str
    description: str = ""
    examiner: str = ""
    organization: str = ""
    case_type: str = "incident"          # incident | forensic | threat_hunt
    priority: str = "medium"             # low | medium | high | critical
    tags: list[str] = Field(default_factory=list)


class Case(IRISBaseModel):
    case_id: str
    investigation_id: str                # links to all events/alerts
    name: str
    description: str = ""
    examiner: str = ""
    organization: str = ""
    case_type: str = "incident"
    priority: str = "medium"
    status: str = "open"                 # open | in_progress | closed
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_count: int = 0
    alert_count: int = 0


class CaseListResponse(IRISBaseModel):
    items: list[Case]
    total: int
