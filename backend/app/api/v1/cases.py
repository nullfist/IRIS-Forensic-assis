from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from backend.app.bootstrap import get_store
from backend.app.repository.memory_store import MemoryStore
from backend.app.schemas.ingestion import Case, CaseCreate, CaseListResponse

router = APIRouter(prefix="/cases", tags=["cases"])


@router.get("", response_model=CaseListResponse)
def list_cases(store: MemoryStore = Depends(get_store)) -> CaseListResponse:
    cases = store.get_all_cases()
    return CaseListResponse(items=cases, total=len(cases))


@router.post("", response_model=Case)
def create_case(
    payload: CaseCreate,
    store: MemoryStore = Depends(get_store),
) -> Case:
    case_id = str(uuid.uuid4())
    investigation_id = f"case-{case_id[:8]}"
    now = datetime.now(timezone.utc)
    case = Case(
        case_id=case_id,
        investigation_id=investigation_id,
        name=payload.name,
        description=payload.description,
        examiner=payload.examiner,
        organization=payload.organization,
        case_type=payload.case_type,
        priority=payload.priority,
        status="open",
        tags=payload.tags,
        created_at=now,
        updated_at=now,
    )
    store.upsert_case(case)
    return case


@router.get("/{case_id}", response_model=Case)
def get_case(case_id: str, store: MemoryStore = Depends(get_store)) -> Case:
    case = store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    case.event_count = len(store.get_events(case.investigation_id))
    case.alert_count = len(store.get_alerts(case.investigation_id))
    return case


@router.patch("/{case_id}/status", response_model=Case)
def update_case_status(
    case_id: str,
    status: str,
    store: MemoryStore = Depends(get_store),
) -> Case:
    case = store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    case.status = status
    case.updated_at = datetime.now(timezone.utc)
    store.upsert_case(case)
    return case


@router.delete("/{case_id}")
def delete_case(case_id: str, store: MemoryStore = Depends(get_store)) -> dict:
    if not store.delete_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    return {"deleted": case_id}
