from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import Field

from backend.app.models.enums import AttackPhase, EntityType, EventCategory, EventSource, SeverityLevel
from backend.app.schemas.base import IRISBaseModel, InvestigationScopedModel


class RawSourceReference(IRISBaseModel):
    record_index: int | None = None
    source_file: str | None = None
    source_id: str | None = None
    channel: str | None = None


class ParserProvenance(IRISBaseModel):
    parser_name: str
    parser_version: str = "1.0"
    parsed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    timestamp_fidelity: str = "high"
    notes: list[str] = Field(default_factory=list)


class EventEvidence(IRISBaseModel):
    kind: str
    summary: str
    artifact: str | None = None
    values: dict[str, Any] = Field(default_factory=dict)


class EntityRef(IRISBaseModel):
    entity_id: str
    entity_type: EntityType
    name: str
    display_name: str | None = None
    host: str | None = None
    risk_score: float = 0.0
    attributes: dict[str, Any] = Field(default_factory=dict)


class ProcessContext(IRISBaseModel):
    process_guid: str | None = None
    pid: int | None = None
    image: str | None = None
    original_file_name: str | None = None
    command_line: str | None = None
    current_directory: str | None = None
    integrity_level: str | None = None
    parent_process_guid: str | None = None
    parent_pid: int | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)


class NetworkContext(IRISBaseModel):
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    direction: str | None = None
    domain: str | None = None
    sni: str | None = None
    url: str | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None


class FileContext(IRISBaseModel):
    path: str | None = None
    target_path: str | None = None
    extension: str | None = None
    operation: str | None = None
    file_hashes: dict[str, str] = Field(default_factory=dict)
    size_bytes: int | None = None


class RegistryContext(IRISBaseModel):
    key_path: str | None = None
    value_name: str | None = None
    value_data: str | None = None
    operation: str | None = None


class NormalizedEvent(InvestigationScopedModel):
    event_id: str
    source: EventSource
    category: EventCategory
    event_type: str
    timestamp: datetime
    observed_at: datetime | None = None
    severity: SeverityLevel = SeverityLevel.INFO
    attack_phase: AttackPhase | None = None
    title: str
    description: str | None = None
    host: str | None = None
    user: str | None = None
    session_id: str | None = None
    process: ProcessContext | None = None
    network: NetworkContext | None = None
    file: FileContext | None = None
    registry: RegistryContext | None = None
    entities: list[EntityRef] = Field(default_factory=list)
    evidence: list[EventEvidence] = Field(default_factory=list)
    confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    raw_source_reference: RawSourceReference | None = None
    parser_provenance: ParserProvenance
    correlation_keys: list[str] = Field(default_factory=list)


class EventListResponse(IRISBaseModel):
    items: list[NormalizedEvent]
    total: int