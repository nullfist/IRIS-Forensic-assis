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
    ProcessContext,
    RawSourceReference,
)


class EvtxJsonParser(BaseParser):
    """Normalize EVTX-exported JSON records for security and operational telemetry."""

    source_name = EventSource.EVTX

    def can_parse(self, source: str, sample_record: dict[str, Any] | None = None) -> bool:
        if str(source).lower() == EventSource.EVTX:
            return True
        if not sample_record:
            return False
        return "EventID" in sample_record and "Channel" in sample_record

    def parse_records(
        self,
        investigation_id: str,
        records: list[dict[str, Any]],
        artifact_name: str | None = None,
    ) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for index, record in enumerate(records):
            event = self._parse_record(investigation_id, record, index, artifact_name)
            if event:
                events.append(event)
        return events

    def _parse_record(
        self,
        investigation_id: str,
        record: dict[str, Any],
        index: int,
        artifact_name: str | None,
    ) -> NormalizedEvent | None:
        event_id = int(record.get("EventID", 0) or 0)
        channel = str(record.get("Channel", "")).lower()
        timestamp = self._parse_timestamp(record.get("TimeCreated") or record.get("@timestamp"))
        host = record.get("Computer")
        user = record.get("TargetUserName") or record.get("SubjectUserName") or record.get("User")
        event_type = "generic_event"
        category = EventCategory.OTHER
        severity = SeverityLevel.LOW
        phase = AttackPhase.UNKNOWN
        process = None
        network = None
        evidence: list[EventEvidence] = []
        title = f"Windows event {event_id}"

        if event_id == 4624:
            category = EventCategory.AUTHENTICATION
            event_type = "logon_success"
            severity = SeverityLevel.INFO
            phase = AttackPhase.INITIAL_ACCESS
            network = NetworkContext(
                src_ip=record.get("IpAddress"),
                src_port=self._to_int(record.get("IpPort")),
                protocol="tcp",
                direction="inbound",
            )
            title = f"Successful logon for {user or 'unknown user'}"
            evidence.append(
                EventEvidence(
                    kind="auth",
                    summary="Successful logon recorded",
                    values={"logon_type": record.get("LogonType"), "ip_address": record.get("IpAddress")},
                )
            )
        elif event_id == 4697:
            category = EventCategory.SERVICE
            event_type = "service_install"
            severity = SeverityLevel.HIGH
            phase = AttackPhase.LATERAL_MOVEMENT
            title = f"Service installed on {host or 'endpoint'}"
            evidence.append(
                EventEvidence(
                    kind="service",
                    summary="Service installation event",
                    values={"service_name": record.get("ServiceName"), "service_file_name": record.get("ServiceFileName")},
                )
            )
        elif event_id == 4698:
            category = EventCategory.TASK
            event_type = "scheduled_task_create"
            severity = SeverityLevel.MEDIUM
            phase = AttackPhase.PERSISTENCE
            title = f"Scheduled task created on {host or 'endpoint'}"
            evidence.append(
                EventEvidence(
                    kind="task",
                    summary="Scheduled task creation recorded",
                    values={"task_name": record.get("TaskName"), "task_content": record.get("TaskContent")},
                )
            )
        elif event_id in {4103, 4104} or "powershell" in channel:
            category = EventCategory.SCRIPT
            event_type = "powershell_activity"
            severity = SeverityLevel.HIGH
            phase = AttackPhase.EXECUTION
            script_text = record.get("ScriptBlockText") or record.get("Payload") or record.get("Message")
            process = ProcessContext(
                image=record.get("HostApplication") or "powershell.exe",
                command_line=record.get("HostApplication") or script_text,
                pid=self._to_int(record.get("ProcessId")),
            )
            title = "PowerShell activity observed"
            evidence.append(
                EventEvidence(
                    kind="script",
                    summary="PowerShell execution details",
                    values={"script_block": script_text},
                )
            )
        else:
            return None

        entities = self._build_entities(record, host, user, process, network)
        return NormalizedEvent(
            event_id=self._make_event_id(investigation_id, record, index),
            investigation_id=investigation_id,
            source=EventSource.EVTX,
            category=category,
            event_type=event_type,
            timestamp=timestamp,
            observed_at=timestamp,
            severity=severity,
            attack_phase=phase,
            title=title,
            description=record.get("Message"),
            host=host,
            user=user,
            process=process,
            network=network,
            entities=entities,
            evidence=evidence,
            confidence=0.82,
            tags=["evtx", event_type, channel],
            raw_data=record,
            raw_source_reference=RawSourceReference(
                record_index=index,
                source_file=artifact_name,
                source_id=record.get("EventRecordID"),
                channel=record.get("Channel"),
            ),
            parser_provenance=ParserProvenance(
                parser_name=self.__class__.__name__,
                timestamp_fidelity="high",
            ),
            correlation_keys=[value for value in [host, user, record.get("LogonId"), record.get("SubjectLogonId")] if value],
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
    def _make_event_id(investigation_id: str, record: dict[str, Any], index: int) -> str:
        basis = f"{investigation_id}:{record.get('EventRecordID') or index}:{record.get('TimeCreated')}:{record.get('EventID')}"
        return hashlib.sha1(basis.encode("utf-8")).hexdigest()

    @staticmethod
    def _to_int(value: Any) -> int | None:
        try:
            return int(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _build_entities(
        record: dict[str, Any],
        host: str | None,
        user: str | None,
        process: ProcessContext | None,
        network: NetworkContext | None,
    ) -> list[EntityRef]:
        entities: list[EntityRef] = []
        if host:
            entities.append(EntityRef(entity_id=f"host:{host.lower()}", entity_type="host", name=host))
        if user:
            entities.append(EntityRef(entity_id=f"user:{user.lower()}", entity_type="user", name=user))
        if process and process.image:
            entities.append(
                EntityRef(
                    entity_id=f"process:{process.image.lower()}:{process.pid or 'unknown'}",
                    entity_type="process",
                    name=process.image,
                    host=host,
                    attributes={"command_line": process.command_line},
                )
            )
        if network and network.src_ip:
            entities.append(EntityRef(entity_id=f"ip:{network.src_ip}", entity_type="ip", name=network.src_ip))
        service_name = record.get("ServiceName")
        if service_name:
            entities.append(EntityRef(entity_id=f"service:{service_name.lower()}", entity_type="service", name=service_name))
        task_name = record.get("TaskName")
        if task_name:
            entities.append(EntityRef(entity_id=f"task:{task_name.lower()}", entity_type="task", name=task_name))
        return entities