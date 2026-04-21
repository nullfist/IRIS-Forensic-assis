from __future__ import annotations

from typing import Any

from pydantic import Field

from backend.app.models.enums import EntityType, SeverityLevel
from backend.app.schemas.base import IRISBaseModel


class GraphNode(IRISBaseModel):
    id: str
    label: str
    type: EntityType
    severity: SeverityLevel = SeverityLevel.INFO
    risk_score: float = 0.0
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(IRISBaseModel):
    id: str
    source: str
    target: str
    relationship: str
    weight: float = 1.0
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphFilters(IRISBaseModel):
    host: str | None = None
    user: str | None = None
    severity: SeverityLevel | None = None
    source: str | None = None
    start_time: str | None = None
    end_time: str | None = None


class AttackPathRequest(IRISBaseModel):
    source_entity_id: str
    target_entity_id: str
    investigation_id: str | None = None
    max_depth: int = 5


class AttackPath(IRISBaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    score: float = 0.0
    rationale: str | None = None


class GraphResponse(IRISBaseModel):
    investigation_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    total_nodes: int = 0
    total_edges: int = 0

    def model_post_init(self, __context: object) -> None:
        if not self.total_nodes:
            self.total_nodes = len(self.nodes)
        if not self.total_edges:
            self.total_edges = len(self.edges)


class AttackPathResponse(IRISBaseModel):
    investigation_id: str | None = None
    paths: list[AttackPath]