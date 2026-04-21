from __future__ import annotations

from collections import defaultdict
from datetime import timezone

from dateutil import parser as date_parser

from backend.app.graph.neo4j_client import Neo4jGraphClient
from backend.app.models.enums import EntityType, SeverityLevel
from backend.app.repository.memory_store import MemoryStore
from backend.app.schemas.events import NormalizedEvent
from backend.app.schemas.graph import AttackPath, AttackPathResponse, GraphEdge, GraphFilters, GraphNode, GraphResponse


class GraphService:
    """Project normalized events into analyst-facing graph structures."""

    def __init__(self, store: MemoryStore, neo4j_client: Neo4jGraphClient | None = None) -> None:
        self.store = store
        self.neo4j_client = neo4j_client

    def build_graph(self, events: list[NormalizedEvent]) -> GraphResponse:
        if not events:
            return GraphResponse(
                investigation_id="unknown",
                nodes=[],
                edges=[],
            )

        investigation_id = events[0].investigation_id
        nodes: dict[str, GraphNode] = {}
        edges: dict[str, GraphEdge] = {}

        for event in events:
            for entity in event.entities:
                nodes.setdefault(
                    entity.entity_id,
                    GraphNode(
                        id=entity.entity_id,
                        label=entity.display_name or entity.name,
                        type=entity.entity_type,
                        severity=event.severity,
                        risk_score=entity.risk_score,
                        properties=entity.attributes,
                    ),
                )

            for left, right in zip(event.entities, event.entities[1:], strict=False):
                edge_id = f"{left.entity_id}->{right.entity_id}-{event.event_id}"
                edges[edge_id] = GraphEdge(
                    id=edge_id,
                    source=left.entity_id,
                    target=right.entity_id,
                    relationship=event.event_type,
                    weight=max(event.confidence, 0.1),
                    properties={"event_id": event.event_id, "timestamp": event.timestamp.isoformat()},
                )

        if self.neo4j_client:
            self.neo4j_client.upsert_events(events)

        return GraphResponse(
            investigation_id=investigation_id,
            nodes=list(nodes.values()),
            edges=list(edges.values()),
        )

    def get_graph(self, investigation_id: str, filters: GraphFilters | None = None) -> GraphResponse:
        events = self.store.get_events(investigation_id)
        filtered_events = [event for event in events if self._matches_filters(event, filters)]
        return self.build_graph(filtered_events)

    def find_attack_paths(
        self,
        source_entity_id: str,
        target_entity_id: str,
        investigation_id: str | None = None,
        max_depth: int = 5,
    ) -> AttackPathResponse:
        if self.neo4j_client and self.neo4j_client.available:
            raw_paths = self.neo4j_client.find_attack_paths(source_entity_id, target_entity_id, max_depth=max_depth)
            if raw_paths:
                return AttackPathResponse(
                    investigation_id=investigation_id,
                    paths=[
                        AttackPath(nodes=[], edges=[], score=0.8, rationale="Path returned from Neo4j traversal.")
                        for _ in raw_paths
                    ],
                )

        graph = self.get_graph(investigation_id or self._infer_investigation_id(source_entity_id, target_entity_id))
        adjacency: dict[str, list[GraphEdge]] = defaultdict(list)
        for edge in graph.edges:
            adjacency[edge.source].append(edge)

        queue: list[tuple[str, list[str], list[GraphEdge]]] = [(source_entity_id, [source_entity_id], [])]
        found_paths: list[AttackPath] = []

        while queue and len(found_paths) < 5:
            node_id, path_nodes, path_edges = queue.pop(0)
            if len(path_nodes) > max_depth + 1:
                continue
            if node_id == target_entity_id:
                resolved_nodes = [next(node for node in graph.nodes if node.id == nid) for nid in path_nodes if any(node.id == nid for node in graph.nodes)]
                found_paths.append(
                    AttackPath(
                        nodes=resolved_nodes,
                        edges=path_edges,
                        score=sum(edge.weight for edge in path_edges) or 0.1,
                        rationale="In-memory graph traversal path.",
                    )
                )
                continue
            for edge in adjacency.get(node_id, []):
                if edge.target in path_nodes:
                    continue
                queue.append((edge.target, [*path_nodes, edge.target], [*path_edges, edge]))

        return AttackPathResponse(investigation_id=investigation_id, paths=found_paths)

    @staticmethod
    def _matches_filters(event: NormalizedEvent, filters: GraphFilters | None) -> bool:
        if not filters:
            return True
        if filters.host and event.host != filters.host:
            return False
        if filters.user and event.user != filters.user:
            return False
        if filters.severity and event.severity != filters.severity:
            return False
        if filters.source and str(event.source) != filters.source:
            return False
        if filters.start_time:
            parsed_start = GraphService._parse_datetime(filters.start_time)
            if parsed_start and event.timestamp < parsed_start:
                return False
        if filters.end_time:
            parsed_end = GraphService._parse_datetime(filters.end_time)
            if parsed_end and event.timestamp > parsed_end:
                return False
        return True

    @staticmethod
    def _parse_datetime(value: str):
        parsed = date_parser.parse(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    def _infer_investigation_id(self, source_entity_id: str, target_entity_id: str) -> str:
        for investigation_id, events in self.store.events_by_investigation.items():
            entities = {entity.entity_id for event in events for entity in event.entities}
            if source_entity_id in entities or target_entity_id in entities:
                return investigation_id
        return "unknown"