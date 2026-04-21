from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.app.bootstrap import get_reasoning_engine, get_store
from backend.app.explainability.reasoning_engine import ReasoningEngine
from backend.app.models.enums import AlertStatus, AttackPhase, SeverityLevel
from backend.app.repository.memory_store import MemoryStore
from backend.app.schemas.alerts import AlertListResponse, ExplanationResponse

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertListResponse)
def list_alerts(
    investigation_id: str | None = Query(default=None),
    severity: SeverityLevel | None = Query(default=None),
    phase: AttackPhase | None = Query(default=None),
    status: AlertStatus | None = Query(default=None),
    host: str | None = Query(default=None),
    user: str | None = Query(default=None),
    store: MemoryStore = Depends(get_store),
) -> AlertListResponse:
    alerts = store.get_alerts(investigation_id)
    filtered = [
        alert
        for alert in alerts
        if (not severity or alert.severity == severity)
        and (not phase or alert.phase == phase)
        and (not status or alert.status == status)
        and (not host or alert.host == host)
        and (not user or alert.user == user)
    ]
    return AlertListResponse(items=filtered, total=len(filtered))


@router.get("/{alert_id}/explanation", response_model=ExplanationResponse)
def get_alert_explanation(
    alert_id: str,
    store: MemoryStore = Depends(get_store),
    reasoning_engine: ReasoningEngine = Depends(get_reasoning_engine),
) -> ExplanationResponse:
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    supporting_events = [
        event
        for event in store.get_events(alert.investigation_id)
        if event.event_id in set(alert.source_event_ids)
    ]
    return reasoning_engine.explain_alert(alert, supporting_events)