from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from backend.app.bootstrap import get_store
from backend.app.repository.memory_store import MemoryStore
from backend.app.services.correlation_intelligence_service import CorrelationIntelligenceService
from backend.app.services.root_cause_service import RootCauseService
from backend.app.services.story_mode_service import StoryModeService

router = APIRouter(prefix="/analysis", tags=["analysis"])

_root_cause_svc = RootCauseService()
_story_svc = StoryModeService()
_corr_intel_svc = CorrelationIntelligenceService()


@router.get("/root-cause")
def get_root_cause(
    investigation_id: str | None = Query(default=None),
    store: MemoryStore = Depends(get_store),
) -> dict:
    """
    Identify the most likely attack origin event.
    Returns the entry-point event, confidence score, reasoning, and attack chain.
    """
    events = store.get_events(investigation_id)
    result = _root_cause_svc.identify(events)
    if result is None:
        return {
            "found": False,
            "message": "Not enough events to determine attack origin.",
        }
    return {"found": True, **result.to_dict()}


@router.get("/story")
def get_attack_story(
    investigation_id: str | None = Query(default=None),
    store: MemoryStore = Depends(get_store),
) -> dict:
    """
    Generate a human-readable attack narrative grouped by MITRE ATT&CK phase.
    Each chapter covers one phase with headline, narrative paragraph, key events, and linked alerts.
    """
    events = store.get_events(investigation_id)
    alerts = store.get_alerts(investigation_id)
    return _story_svc.generate(events, alerts, investigation_id or "unknown")


@router.get("/correlation-intel")
def get_correlation_intel(
    investigation_id: str | None = Query(default=None),
    store: MemoryStore = Depends(get_store),
) -> dict:
    """
    Expose hidden event relationships with explicit human-readable reasoning.
    Finds cross-host user activity, process chains, shared C2 destinations,
    shared file hashes, and temporal activity bursts.
    """
    events = store.get_events(investigation_id)
    return _corr_intel_svc.analyze(events)
