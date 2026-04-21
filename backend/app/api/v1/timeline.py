from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from backend.app.bootstrap import get_store, get_timeline_service
from backend.app.repository.memory_store import MemoryStore
from backend.app.schemas.timeline import ReplayResponse, TimelineResponse
from backend.app.services.timeline_service import TimelineService

router = APIRouter(prefix="/timeline", tags=["timeline"])


@router.get("", response_model=TimelineResponse)
def get_timeline(
    investigation_id: str | None = Query(default=None),
    timeline_service: TimelineService = Depends(get_timeline_service),
    store: MemoryStore = Depends(get_store),
) -> TimelineResponse:
    events = store.get_events(investigation_id)
    return timeline_service.build_timeline(investigation_id or "default", events)


@router.get("/replay", response_model=ReplayResponse)
def get_timeline_replay(
    investigation_id: str | None = Query(default=None),
    position: int = Query(default=0, ge=0),
    timeline_service: TimelineService = Depends(get_timeline_service),
    store: MemoryStore = Depends(get_store),
) -> ReplayResponse:
    events = store.get_events(investigation_id)
    return timeline_service.build_replay(investigation_id or "default", events, replay_position=position)