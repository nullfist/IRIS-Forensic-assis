from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from backend.app.schemas.events import NormalizedEvent


class BaseParser(ABC):
    """Abstract parser interface for source-specific normalization."""

    source_name: str = "unknown"

    @abstractmethod
    def can_parse(self, source: str, sample_record: dict[str, Any] | None = None) -> bool:
        """Return whether this parser can handle the source and record shape."""

    @abstractmethod
    def parse_records(
        self,
        investigation_id: str,
        records: list[dict[str, Any]],
        artifact_name: str | None = None,
    ) -> list[NormalizedEvent]:
        """Parse raw records into canonical normalized events."""