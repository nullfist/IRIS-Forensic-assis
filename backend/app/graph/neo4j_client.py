from __future__ import annotations

from typing import Any

from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError

from backend.app.core.logging import get_logger
from backend.app.core.config import Settings
from backend.app.schemas.events import NormalizedEvent

logger = get_logger(__name__)


class Neo4jGraphClient:
    """Thin Neo4j wrapper that degrades gracefully when the graph is unavailable."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._driver = None
        self.available = False

    def connect(self) -> None:
        try:
            self._driver = GraphDatabase.driver(
                self.settings.neo4j_uri,
                auth=(self.settings.neo4j_user, self.settings.neo4j_password),
            )
            self._driver.verify_connectivity()
            self.available = True
        except Exception as exc:  # pragma: no cover - defensive fallback
            self.available = False
            logger.warning(
                "Neo4j unavailable; graph operations will use in-memory fallback",
                extra={"extra_data": {"error": str(exc), "uri": self.settings.neo4j_uri}},
            )

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
        self.available = False

    def upsert_events(self, events: list[NormalizedEvent]) -> None:
        if not self.available or not self._driver:
            return

        query = """
        UNWIND $events AS event
        MERGE (e:Event {event_id: event.event_id})
        SET e += event.properties
        FOREACH (entity IN event.entities |
            MERGE (n:Entity {entity_id: entity.entity_id})
            SET n += entity.properties
            MERGE (n)-[:OBSERVED_IN]->(e)
        )
        """
        payload = []
        for event in events:
            payload.append(
                {
                    "event_id": event.event_id,
                    "properties": {
                        "investigation_id": event.investigation_id,
                        "source": str(event.source),
                        "category": str(event.category),
                        "event_type": event.event_type,
                        "timestamp": event.timestamp.isoformat(),
                        "host": event.host,
                        "user": event.user,
                    },
                    "entities": [
                        {
                            "entity_id": entity.entity_id,
                            "properties": {
                                "name": entity.name,
                                "type": str(entity.entity_type),
                                "host": entity.host,
                            },
                        }
                        for entity in event.entities
                    ],
                }
            )
        self._run_write(query, {"events": payload})

    def find_attack_paths(
        self,
        source_entity_id: str,
        target_entity_id: str,
        max_depth: int = 5,
    ) -> list[dict[str, Any]]:
        if not self.available or not self._driver:
            return []

        query = """
        MATCH p = (s:Entity {entity_id: $source_entity_id})-[*..$max_depth]-(t:Entity {entity_id: $target_entity_id})
        RETURN p
        LIMIT 5
        """
        try:
            with self._driver.session() as session:
                result = session.run(
                    query,
                    {
                        "source_entity_id": source_entity_id,
                        "target_entity_id": target_entity_id,
                        "max_depth": max_depth,
                    },
                )
                return [record.data() for record in result]
        except Neo4jError as exc:  # pragma: no cover - defensive fallback
            logger.warning(
                "Neo4j path query failed",
                extra={"extra_data": {"error": str(exc)}},
            )
            return []

    def _run_write(self, query: str, params: dict[str, Any]) -> None:
        try:
            with self._driver.session() as session:
                session.run(query, params)
        except Neo4jError as exc:  # pragma: no cover - defensive fallback
            logger.warning(
                "Neo4j write failed",
                extra={"extra_data": {"error": str(exc)}},
            )