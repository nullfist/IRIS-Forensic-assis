from __future__ import annotations

from datetime import datetime

from pydantic import Field

from backend.app.models.enums import AttackPhase, SeverityLevel
from backend.app.schemas.base import IRISBaseModel
from backend.app.schemas.events import NormalizedEvent


class TimelineEntry(IRISBaseModel):
    entry_id: str
    event_id: str = ""  # alias used by frontend
    timestamp: datetime
    phase: AttackPhase
    title: str
    summary: str
    severity: SeverityLevel
    source: str = ""  # populated from first event source
    event_ids: list[str] = Field(default_factory=list)
    host: str | None = None
    user: str | None = None
    events: list[NormalizedEvent] = Field(default_factory=list)


class TimelinePhaseGroup(IRISBaseModel):
    phase: AttackPhase
    started_at: datetime | None = None
    ended_at: datetime | None = None
    # Frontend-compatible aliases
    start_time: datetime | None = None
    end_time: datetime | None = None
    entries: list[TimelineEntry] = Field(default_factory=list)
    event_count: int = 0

    def model_post_init(self, __context: object) -> None:
        if self.start_time is None:
            self.start_time = self.started_at
        if self.end_time is None:
            self.end_time = self.ended_at


class TimelineResponse(IRISBaseModel):
    investigation_id: str
    entries: list[TimelineEntry]
    phases: list[TimelinePhaseGroup]
    total: int


class ReplayFrame(IRISBaseModel):
    index: int
    total: int
    current_timestamp: datetime | None = None
    current_entry: TimelineEntry | None = None
    surrounding_entries: list[TimelineEntry] = Field(default_factory=list)


class ReplayResponse(IRISBaseModel):
    investigation_id: str
    replay_position: int
    frame: ReplayFrame