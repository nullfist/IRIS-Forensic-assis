from __future__ import annotations

from typing import Any

from backend.app.core.logging import get_logger
from backend.app.models.enums import EventSource
from backend.app.parsers.base import BaseParser
from backend.app.parsers.evtx_parser import EvtxJsonParser
from backend.app.parsers.pcap_parser import PcapMetadataParser
from backend.app.parsers.sysmon_parser import SysmonParser
from backend.app.schemas.events import NormalizedEvent
from backend.app.services.entity_extraction_service import EntityExtractionService

logger = get_logger(__name__)


class NormalizationService:
    """Coordinates source-specific parsers and canonical entity extraction."""

    def __init__(
        self,
        parsers: list[BaseParser] | None = None,
        entity_extraction_service: EntityExtractionService | None = None,
    ) -> None:
        self.parsers = parsers or [SysmonParser(), EvtxJsonParser(), PcapMetadataParser()]
        self.entity_extraction_service = entity_extraction_service or EntityExtractionService()

    def normalize(
        self,
        source: EventSource | str,
        records: list[dict[str, Any]],
        investigation_id: str = "default-investigation",
        artifact_name: str | None = None,
    ) -> list[NormalizedEvent]:
        parser = self._select_parser(source, records[0] if records else None)
        if not parser:
            logger.warning(
                "No parser found for records",
                extra={"extra_data": {"source": source, "artifact_name": artifact_name}},
            )
            return []

        events = parser.parse_records(
            investigation_id=investigation_id,
            records=records,
            artifact_name=artifact_name,
        )
        for event in events:
            self.entity_extraction_service.extract_entities(event)
        return events

    def _select_parser(self, source: EventSource | str, sample_record: dict[str, Any] | None) -> BaseParser | None:
        normalized_source = str(source).lower()
        for parser in self.parsers:
            if parser.can_parse(normalized_source, sample_record):
                return parser
        return None