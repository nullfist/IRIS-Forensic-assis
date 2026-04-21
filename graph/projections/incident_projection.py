"""Neo4j query preset helpers for IRIS investigative views."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

@dataclass(slots=True)
class IncidentProjection:
    name: str
    description: str
    node_labels: list[str]
    relationship_types: list[str]
    filters: dict[str, Any] = field(default_factory=dict)


DEFAULT_PROJECTIONS: dict[str, IncidentProjection] = {
    "default_investigation": IncidentProjection(
        name="default_investigation",
        description="Balanced projection for graph panel rendering around events, entities, and alerts.",
        node_labels=["Investigation", "Event", "Host", "User", "Process", "File", "Registry", "IP", "Domain", "Alert"],
        relationship_types=["CONTAINS_EVENT", "CONTAINS_ALERT", "INVOLVES", "SUPPORTED_BY", "CHILD_OF", "CONNECTED_TO", "OBSERVED_ON", "ACTED_AS"],
    ),
    "attack_path": IncidentProjection(
        name="attack_path",
        description="Traversal-oriented projection optimized for multi-hop adversary path discovery.",
        node_labels=["Host", "User", "Process", "IP", "Domain", "Alert"],
        relationship_types=["CHILD_OF", "CONNECTED_TO", "AUTHENTICATED_TO", "TARGETS", "SUPPORTED_BY", "COMMUNICATED_WITH"],
    ),
    "timeline_context": IncidentProjection(
        name="timeline_context",
        description="Projection favoring event chronology and host/process lineage.",
        node_labels=["Event", "Host", "User", "Process", "File", "Registry"],
        relationship_types=["INVOLVES", "OBSERVED_ON", "ACTED_AS", "CHILD_OF"],
    ),
}


def get_projection(name: str = "default_investigation") -> IncidentProjection:
    """Return a named projection, falling back to the default investigation view."""
    return DEFAULT_PROJECTIONS.get(name, DEFAULT_PROJECTIONS["default_investigation"])


def build_projection_payload(name: str = "default_investigation", **filters: Any) -> dict[str, Any]:
    """Build a serializable projection payload for service or API use."""
    projection = get_projection(name)
    merged_filters = {**projection.filters, **{key: value for key, value in filters.items() if value is not None}}
    return {
        "name": projection.name,
        "description": projection.description,
        "node_labels": projection.node_labels,
        "relationship_types": projection.relationship_types,
        "filters": merged_filters,
    }