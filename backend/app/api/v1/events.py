from __future__ import annotations

from datetime import datetime, timezone

from dateutil import parser as date_parser
from fastapi import APIRouter, Depends, Query

from backend.app.bootstrap import get_store
from backend.app.models.enums import EventSource, SeverityLevel
from backend.app.repository.memory_store import MemoryStore
from backend.app.schemas.events import EventListResponse, NormalizedEvent

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=EventListResponse)
def list_events(
    investigation_id: str | None = Query(default=None),
    source: EventSource | None = Query(default=None),
    host: str | None = Query(default=None),
    user: str | None = Query(default=None),
    severity: SeverityLevel | None = Query(default=None),
    start_time: str | None = Query(default=None),
    end_time: str | None = Query(default=None),
    store: MemoryStore = Depends(get_store),
) -> EventListResponse:
    events = store.get_events(investigation_id)
    filtered = [
        event
        for event in events
        if _matches_filters(
            event=event,
            source=source,
            host=host,
            user=user,
            severity=severity,
            start_time=start_time,
            end_time=end_time,
        )
    ]
    return EventListResponse(items=filtered, total=len(filtered))


def _matches_filters(
    event: NormalizedEvent,
    source: EventSource | None,
    host: str | None,
    user: str | None,
    severity: SeverityLevel | None,
    start_time: str | None,
    end_time: str | None,
) -> bool:
    if source and event.source != source:
        return False
    if host and event.host != host:
        return False
    if user and event.user != user:
        return False
    if severity and event.severity != severity:
        return False
    if start_time:
        parsed_start = _parse_datetime(start_time)
        if parsed_start and event.timestamp < parsed_start:
            return False
    if end_time:
        parsed_end = _parse_datetime(end_time)
        if parsed_end and event.timestamp > parsed_end:
            return False
    return True


def _parse_datetime(value: str) -> datetime | None:
    try:
        parsed = date_parser.parse(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None