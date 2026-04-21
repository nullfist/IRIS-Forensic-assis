from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """Compatibility helper for string-valued enums."""

    def __str__(self) -> str:
        return str(self.value)


class EventSource(StrEnum):
    SYSMON = "sysmon"
    EVTX = "evtx"
    PCAP = "pcap"
    EDR = "edr"
    WINDOWS_SECURITY = "windows_security"
    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
    XML = "xml"
    CSV = "csv"
    GENERIC = "generic"
    UNKNOWN = "unknown"


class EventCategory(StrEnum):
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    REGISTRY = "registry"
    AUTHENTICATION = "authentication"
    SERVICE = "service"
    TASK = "task"
    SCRIPT = "script"
    ALERT = "alert"
    OTHER = "other"


class SeverityLevel(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackPhase(StrEnum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    UNKNOWN = "unknown"


class EntityType(StrEnum):
    HOST = "host"
    USER = "user"
    PROCESS = "process"
    FILE = "file"
    IP = "ip"
    DOMAIN = "domain"
    SERVICE = "service"
    TASK = "task"
    REGISTRY_KEY = "registry_key"
    ALERT = "alert"


class AlertStatus(StrEnum):
    NEW = "new"
    IN_REVIEW = "in_review"
    CONFIRMED = "confirmed"
    SUPPRESSED = "suppressed"
    CLOSED = "closed"