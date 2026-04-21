from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from dateutil import parser as date_parser

from backend.app.models.enums import AttackPhase, EventCategory, EventSource, SeverityLevel
from backend.app.parsers.base import BaseParser
from backend.app.schemas.events import (
    EntityRef,
    EventEvidence,
    NetworkContext,
    NormalizedEvent,
    ParserProvenance,
    RawSourceReference,
)


class PcapMetadataParser(BaseParser):
    """Normalize lightweight PCAP flow metadata into network events."""

    source_name = EventSource.PCAP

    def can_parse(self, source: str, sample_record: dict[str, Any] | None = None) -> bool:
        if str(source).lower() == EventSource.PCAP:
            return True
        if not sample_record:
            return False
        fields = {"src_ip", "dst_ip", "protocol"}
        return fields.issubset(set(sample_record.keys()))

    def parse_records(
        self,
        investigation_id: str,
        records: list[dict[str, Any]],
        artifact_name: str | None = None,
    ) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for index, record in enumerate(records):
            events.append(self._parse_record(investigation_id, record, index, artifact_name))
        return events

    def _parse_record(
        self,
        investigation_id: str,
        record: dict[str, Any],
        index: int,
        artifact_name: str | None,
    ) -> NormalizedEvent:
        timestamp = self._parse_timestamp(
            record.get("timestamp") or record.get("start_time") or record.get("@timestamp")
        )
        host = record.get("sensor") or record.get("src_host")
        domain = record.get("domain") or record.get("sni") or record.get("hostname")
        bytes_sent = self._to_int(record.get("bytes_sent") or record.get("orig_bytes") or record.get("bytes_out"))
        bytes_received = self._to_int(record.get("bytes_received") or record.get("resp_bytes") or record.get("bytes_in"))
        dst_port = self._to_int(record.get("dst_port") or record.get("dest_port"))
        severity = SeverityLevel.MEDIUM if (bytes_sent or 0) > 1_000_000 else SeverityLevel.LOW
        phase = AttackPhase.EXFILTRATION if (bytes_sent or 0) > 1_000_000 else AttackPhase.DISCOVERY

        network = NetworkContext(
            src_ip=record.get("src_ip"),
            src_port=self._to_int(record.get("src_port")),
            dst_ip=record.get("dst_ip"),
            dst_port=dst_port,
            protocol=str(record.get("protocol", "tcp")).lower(),
            direction=record.get("direction") or "outbound",
            domain=domain,
            sni=record.get("sni"),
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
        )
        evidence = [
            EventEvidence(
                kind="flow",
                summary="Observed flow metadata",
                values={
                    "src_ip": network.src_ip,
                    "dst_ip": network.dst_ip,
                    "dst_port": network.dst_port,
                    "bytes_sent": bytes_sent,
                    "bytes_received": bytes_received,
                },
            )
        ]
        return NormalizedEvent(
            event_id=self._make_event_id(investigation_id, record, index),
            investigation_id=investigation_id,
            source=EventSource.PCAP,
            category=EventCategory.NETWORK,
            event_type="network_flow",
            timestamp=timestamp,
            observed_at=timestamp,
            severity=severity,
            attack_phase=phase,
            title=f"Network flow {network.src_ip}:{network.src_port} -> {network.dst_ip}:{network.dst_port}",
            description="Flow metadata derived from packet capture",
            host=host,
            network=network,
            entities=self._build_entities(host, network),
            evidence=evidence,
            confidence=0.6,
            tags=["pcap", "network_flow"],
            raw_data=record,
            raw_source_reference=RawSourceReference(
                record_index=index,
                source_file=artifact_name,
                source_id=record.get("flow_id"),
            ),
            parser_provenance=ParserProvenance(
                parser_name=self.__class__.__name__,
                timestamp_fidelity="medium",
                notes=["Timestamp reflects flow observation rather than packet-level fidelity."],
            ),
            correlation_keys=[value for value in [host, network.src_ip, network.dst_ip, domain] if value],
        )

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if not value:
            return datetime.now(timezone.utc)
        parsed = date_parser.parse(str(value))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    @staticmethod
    def _to_int(value: Any) -> int | None:
        try:
            return int(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _make_event_id(investigation_id: str, record: dict[str, Any], index: int) -> str:
        basis = f"{investigation_id}:{record.get('flow_id') or index}:{record.get('src_ip')}:{record.get('dst_ip')}:{record.get('timestamp')}"
        return hashlib.sha1(basis.encode("utf-8")).hexdigest()

    @staticmethod
    def _build_entities(host: str | None, network: NetworkContext) -> list[EntityRef]:
        entities: list[EntityRef] = []
        if host:
            entities.append(EntityRef(entity_id=f"host:{host.lower()}", entity_type="host", name=host))
        if network.src_ip:
            entities.append(EntityRef(entity_id=f"ip:{network.src_ip}", entity_type="ip", name=network.src_ip))
        if network.dst_ip:
            entities.append(EntityRef(entity_id=f"ip:{network.dst_ip}", entity_type="ip", name=network.dst_ip))
        if network.domain:
            entities.append(EntityRef(entity_id=f"domain:{network.domain.lower()}", entity_type="domain", name=network.domain))
        return entities