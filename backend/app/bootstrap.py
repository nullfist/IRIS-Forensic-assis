from __future__ import annotations

from functools import lru_cache

from backend.app.core.config import Settings, get_settings
from backend.app.detection.anomaly_detector import AnomalyDetector
from backend.app.detection.rule_loader import RuleLoader
from backend.app.explainability.reasoning_engine import ReasoningEngine
from backend.app.graph.graph_service import GraphService
from backend.app.graph.neo4j_client import Neo4jGraphClient
from backend.app.repository.memory_store import MemoryStore, get_memory_store
from backend.app.services.correlation_service import CorrelationService
from backend.app.services.detection_service import DetectionService
from backend.app.services.entity_extraction_service import EntityExtractionService
from backend.app.services.ingestion_service import IngestionService
from backend.app.services.normalization_service import NormalizationService
from backend.app.services.risk_scoring_service import RiskScoringService
from backend.app.services.timeline_service import TimelineService


class ServiceContainer:
    """Simple service container for dependency wiring."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.store: MemoryStore = get_memory_store()
        self.entity_extraction_service = EntityExtractionService()
        self.normalization_service = NormalizationService(
            entity_extraction_service=self.entity_extraction_service
        )
        self.correlation_service = CorrelationService()
        self.risk_scoring_service = RiskScoringService()
        self.rule_loader = RuleLoader()
        self.anomaly_detector = AnomalyDetector()
        self.detection_service = DetectionService(
            rule_loader=self.rule_loader,
            anomaly_detector=self.anomaly_detector,
            correlation_service=self.correlation_service,
            risk_scoring_service=self.risk_scoring_service,
        )
        self.neo4j_client = Neo4jGraphClient(settings)
        self.graph_service = GraphService(
            store=self.store,
            neo4j_client=self.neo4j_client,
        )
        self.timeline_service = TimelineService()
        self.reasoning_engine = ReasoningEngine()
        self.ingestion_service = IngestionService(
            store=self.store,
            normalization_service=self.normalization_service,
            detection_service=self.detection_service,
            graph_service=self.graph_service,
        )


@lru_cache(maxsize=1)
def get_container() -> ServiceContainer:
    return ServiceContainer(get_settings())


def initialize_resources() -> None:
    container = get_container()
    container.neo4j_client.connect()


def shutdown_resources() -> None:
    container = get_container()
    container.neo4j_client.close()


def get_ingestion_service() -> IngestionService:
    return get_container().ingestion_service


def get_normalization_service() -> NormalizationService:
    return get_container().normalization_service


def get_entity_extraction_service() -> EntityExtractionService:
    return get_container().entity_extraction_service


def get_correlation_service() -> CorrelationService:
    return get_container().correlation_service


def get_timeline_service() -> TimelineService:
    return get_container().timeline_service


def get_detection_service() -> DetectionService:
    return get_container().detection_service


def get_risk_scoring_service() -> RiskScoringService:
    return get_container().risk_scoring_service


def get_graph_service() -> GraphService:
    return get_container().graph_service


def get_reasoning_engine() -> ReasoningEngine:
    return get_container().reasoning_engine


def get_store() -> MemoryStore:
    return get_container().store