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
    FileContext,
    NetworkContext,
    NormalizedEvent,
    ParserProvenance,
    ProcessContext,
    RawSourceReference,
    RegistryContext,
)


class SysmonParser(BaseParser):
    """Normalize Sysmon-style JSON export records into canonical events."""

    source_name = EventSource.SYSMON

    EVENT_MAP: dict[int, tuple[EventCategory, str]] = {
        1: (EventCategory.PROCESS, "process_create"),
        3: (EventCategory.NETWORK, "network_connect"),
        11: (EventCategory.FILE, "file_create"),
        13: (EventCategory.REGISTRY, "registry_set"),
    }

    def can_parse(self, source: str, sample_record: dict[str, Any] | None = None) -> bool:
        if str(source).lower() == EventSource.SYSMON:
            return True
        if not sample_record:
            return False
        channel = str(sample_record.get("Channel", "")).lower()
        # Explicit Sysmon channel or has ProcessGuid (Sysmon-specific field)
        if "sysmon" in channel or "ProcessGuid" in sample_record:
            return True
        # EventID present but no Channel means it could be Sysmon JSON export
        if "EventID" in sample_record and "Channel" not in sample_record:
            return True
        return False

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
        if event_id not in self.EVENT_MAP:
            return None

        category, event_type = self.EVENT_MAP[event_id]
        timestamp = self._parse_timestamp(
            record.get("UtcTime")
            or record.get("Timestamp")
            or record.get("@timestamp")
            or record.get("EventTime")
        )
        host = record.get("Computer") or record.get("Hostname")
        user = record.get("User") or record.get("TargetUserName")
        process_context = ProcessContext(
            process_guid=record.get("ProcessGuid"),
            pid=self._to_int(record.get("ProcessId")),
            image=record.get("Image"),
            original_file_name=record.get("OriginalFileName"),
            command_line=record.get("CommandLine"),
            current_directory=record.get("CurrentDirectory"),
            integrity_level=record.get("IntegrityLevel"),
            parent_process_guid=record.get("ParentProcessGuid"),
            parent_pid=self._to_int(record.get("ParentProcessId")),
            parent_image=record.get("ParentImage"),
            parent_command_line=record.get("ParentCommandLine"),
            hashes=self._parse_hashes(record.get("Hashes")),
        )

        network_context = None
        file_context = None
        registry_context = None
        evidence: list[EventEvidence] = []

        severity = SeverityLevel.LOW
        attack_phase = AttackPhase.EXECUTION

        if event_id == 3:
            network_context = NetworkContext(
                src_ip=record.get("SourceIp"),
                src_port=self._to_int(record.get("SourcePort")),
                dst_ip=record.get("DestinationIp"),
                dst_port=self._to_int(record.get("DestinationPort")),
                protocol=record.get("Protocol"),
                direction="outbound",
                domain=record.get("DestinationHostname"),
            )
            severity = SeverityLevel.MEDIUM
            if network_context.dst_port in {445, 5985, 5986}:
                attack_phase = AttackPhase.LATERAL_MOVEMENT
            elif network_context.dst_port in {80, 443}:
                attack_phase = AttackPhase.EXFILTRATION
            evidence.append(
                EventEvidence(
                    kind="network",
                    summary="Observed network connection",
                    values={
                        "destination": network_context.dst_ip,
                        "port": network_context.dst_port,
                        "domain": network_context.domain,
                    },
                )
            )
        elif event_id == 11:
            file_context = FileContext(
                path=record.get("TargetFilename"),
                extension=self._extract_extension(record.get("TargetFilename")),
                operation="create",
                file_hashes=self._parse_hashes(record.get("Hashes")),
            )
            severity = SeverityLevel.MEDIUM
            attack_phase = AttackPhase.COLLECTION
            evidence.append(
                EventEvidence(
                    kind="file",
                    summary="Created file artifact",
                    values={"path": file_context.path},
                )
            )
        elif event_id == 13:
            registry_context = RegistryContext(
                key_path=record.get("TargetObject"),
                value_name=record.get("Details"),
                value_data=record.get("Details"),
                operation="set",
            )
            severity = SeverityLevel.MEDIUM
            attack_phase = AttackPhase.PERSISTENCE
            evidence.append(
                EventEvidence(
                    kind="registry",
                    summary="Registry value modified",
                    values={"key_path": registry_context.key_path},
                )
            )
        else:
            evidence.append(
                EventEvidence(
                    kind="process",
                    summary="Observed process creation",
                    values={"image": process_context.image, "command_line": process_context.command_line},
                )
            )
            if process_context.image and any(
                suspicious in process_context.image.lower()
                for suspicious in ("powershell", "cmd.exe", "wscript", "cscript", "rundll32")
            ):
                severity = SeverityLevel.MEDIUM
            if process_context.command_line and "sekurlsa" in process_context.command_line.lower():
                severity = SeverityLevel.HIGH
                attack_phase = AttackPhase.CREDENTIAL_ACCESS

        normalized_event_id = self._make_event_id(investigation_id, record, index)
        return NormalizedEvent(
            event_id=normalized_event_id,
            investigation_id=investigation_id,
            source=EventSource.SYSMON,
            category=category,
            event_type=event_type,
            timestamp=timestamp,
            observed_at=timestamp,
            severity=severity,
            attack_phase=attack_phase,
            title=self._build_title(event_type, process_context.image, host),
            description=record.get("Description"),
            host=host,
            user=user,
            process=process_context,
            network=network_context,
            file=file_context,
            registry=registry_context,
            entities=self._build_entities(host, user, process_context, network_context, file_context, registry_context),
            evidence=evidence,
            confidence=0.9 if event_id in {1, 3, 11, 13} else 0.75,
            tags=["sysmon", event_type],
            raw_data=record,
            raw_source_reference=RawSourceReference(
                record_index=index,
                source_file=artifact_name,
                source_id=record.get("EventRecordID") or record.get("RecordId"),
                channel=record.get("Channel"),
            ),
            parser_provenance=ParserProvenance(parser_name=self.__class__.__name__),
            correlation_keys=[value for value in [host, user, process_context.process_guid, process_context.parent_process_guid] if value],
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
    def _parse_hashes(raw_hashes: Any) -> dict[str, str]:
        if isinstance(raw_hashes, dict):
            return {str(k).upper(): str(v) for k, v in raw_hashes.items()}
        if not raw_hashes:
            return {}
        parsed: dict[str, str] = {}
        for part in str(raw_hashes).split(","):
            if "=" in part:
                algorithm, value = part.split("=", 1)
                parsed[algorithm.strip().upper()] = value.strip()
        return parsed

    @staticmethod
    def _extract_extension(path: str | None) -> str | None:
        if not path or "." not in path:
            return None
        return path.rsplit(".", 1)[-1].lower()

    @staticmethod
    def _make_event_id(investigation_id: str, record: dict[str, Any], index: int) -> str:
        basis = f"{investigation_id}:{record.get('EventRecordID') or record.get('RecordId') or index}:{record.get('UtcTime') or record.get('Timestamp')}"
        return hashlib.sha1(basis.encode("utf-8")).hexdigest()

    @staticmethod
    def _build_title(event_type: str, image: str | None, host: str | None) -> str:
        image_name = image.rsplit("\\", 1)[-1] if image else "process"
        if host:
            return f"{event_type.replace('_', ' ').title()} on {host}: {image_name}"
        return f"{event_type.replace('_', ' ').title()}: {image_name}"

    @staticmethod
    def _build_entities(
        host: str | None,
        user: str | None,
        process: ProcessContext | None,
        network: NetworkContext | None,
        file_context: FileContext | None,
        registry_context: RegistryContext | None,
    ) -> list[EntityRef]:
        entities: list[EntityRef] = []
        if host:
            entities.append(EntityRef(entity_id=f"host:{host.lower()}", entity_type="host", name=host, display_name=host))
        if user:
            entities.append(EntityRef(entity_id=f"user:{user.lower()}", entity_type="user", name=user, display_name=user))
        if process and process.image:
            key = process.process_guid or f"{process.image}:{process.pid or 'unknown'}"
            entities.append(
                EntityRef(
                    entity_id=f"process:{key}",
                    entity_type="process",
                    name=process.image,
                    display_name=process.image.rsplit("\\", 1)[-1],
                    host=host,
                    attributes={"pid": process.pid, "command_line": process.command_line},
                )
            )
        if network and network.dst_ip:
            entities.append(
                EntityRef(
                    entity_id=f"ip:{network.dst_ip}",
                    entity_type="ip",
                    name=network.dst_ip,
                    attributes={"port": network.dst_port, "domain": network.domain},
                )
            )
        if network and network.domain:
            entities.append(EntityRef(entity_id=f"domain:{network.domain.lower()}", entity_type="domain", name=network.domain))
        if file_context and file_context.path:
            entities.append(
                EntityRef(
                    entity_id=f"file:{file_context.path.lower()}",
                    entity_type="file",
                    name=file_context.path,
                    host=host,
                )
            )
        if registry_context and registry_context.key_path:
            entities.append(
                EntityRef(
                    entity_id=f"registry:{registry_context.key_path.lower()}",
                    entity_type="registry_key",
                    name=registry_context.key_path,
                    host=host,
                )
            )
        return entities