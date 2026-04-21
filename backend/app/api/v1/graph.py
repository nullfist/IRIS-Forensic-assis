from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from backend.app.bootstrap import get_graph_service
from backend.app.graph.graph_service import GraphService
from backend.app.schemas.graph import AttackPathRequest, AttackPathResponse, GraphFilters, GraphResponse
from backend.app.models.enums import SeverityLevel

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get("", response_model=GraphResponse)
def get_graph(
    investigation_id: str | None = Query(default=None),
    host: str | None = Query(default=None),
    user: str | None = Query(default=None),
    severity: SeverityLevel | None = Query(default=None),
    source: str | None = Query(default=None),
    start_time: str | None = Query(default=None),
    end_time: str | None = Query(default=None),
    graph_service: GraphService = Depends(get_graph_service),
) -> GraphResponse:
    filters = GraphFilters(
        host=host,
        user=user,
        severity=severity,
        source=source,
        start_time=start_time,
        end_time=end_time,
    )
    return graph_service.get_graph(investigation_id, filters)


@router.post("/attack-paths", response_model=AttackPathResponse)
def find_attack_paths(
    request: AttackPathRequest,
    graph_service: GraphService = Depends(get_graph_service),
) -> AttackPathResponse:
    return graph_service.find_attack_paths(
        source_entity_id=request.source_entity_id,
        target_entity_id=request.target_entity_id,
        investigation_id=request.investigation_id,
        max_depth=request.max_depth,
    )