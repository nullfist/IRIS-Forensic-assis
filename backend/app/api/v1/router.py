from __future__ import annotations

from fastapi import APIRouter

from backend.app.api.v1.alerts import router as alerts_router
from backend.app.api.v1.analysis import router as analysis_router
from backend.app.api.v1.cases import router as cases_router
from backend.app.api.v1.events import router as events_router
from backend.app.api.v1.graph import router as graph_router
from backend.app.api.v1.ingest import router as ingest_router
from backend.app.api.v1.timeline import router as timeline_router

api_router = APIRouter()
api_router.include_router(cases_router)
api_router.include_router(ingest_router)
api_router.include_router(events_router)
api_router.include_router(graph_router)
api_router.include_router(timeline_router)
api_router.include_router(alerts_router)
api_router.include_router(analysis_router)