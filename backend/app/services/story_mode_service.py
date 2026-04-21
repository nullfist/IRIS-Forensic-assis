from __future__ import annotations

from collections import defaultdict
from typing import Any

from backend.app.models.enums import AttackPhase
from backend.app.schemas.alerts import Alert
from backend.app.schemas.events import NormalizedEvent


PHASE_LABELS: dict[str, str] = {
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Theft",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "unknown": "Unknown Activity",
}

PHASE_DESCRIPTIONS: dict[str, str] = {
    "initial_access": "The attacker gained their first foothold into the environment.",
    "execution": "Malicious code was executed on the compromised system.",
    "persistence": "The attacker established mechanisms to maintain access across reboots.",
    "privilege_escalation": "The attacker elevated their privileges to gain broader access.",
    "defense_evasion": "The attacker took steps to avoid detection and bypass security controls.",
    "credential_access": "The attacker harvested credentials to enable further movement.",
    "discovery": "The attacker enumerated the environment to understand the network topology.",
    "lateral_movement": "The attacker moved from the initial host to additional systems.",
    "collection": "The attacker gathered data of interest for exfiltration.",
    "exfiltration": "The attacker transferred data out of the environment to an external destination.",
    "impact": "The attacker caused direct damage or disruption to systems or data.",
    "unknown": "Activity was observed that could not be classified into a specific phase.",
}


class StoryChapter:
    def __init__(
        self,
        step: int,
        phase: str,
        headline: str,
        narrative: str,
        events: list[dict[str, Any]],
        alerts: list[str],
        timestamp_start: str,
        timestamp_end: str,
    ) -> None:
        self.step = step
        self.phase = phase
        self.headline = headline
        self.narrative = narrative
        self.events = events
        self.alerts = alerts
        self.timestamp_start = timestamp_start
        self.timestamp_end = timestamp_end

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "phase": self.phase,
            "headline": self.headline,
            "narrative": self.narrative,
            "events": self.events,
            "alerts": self.alerts,
            "timestamp_start": self.timestamp_start,
            "timestamp_end": self.timestamp_end,
        }


class StoryModeService:
    """
    Generate a human-readable attack story from normalized events and alerts.
    Each chapter covers one MITRE ATT&CK phase with a narrative paragraph,
    key events, and linked alerts.
    """

    PHASE_ORDER = [
        "initial_access", "execution", "persistence", "privilege_escalation",
        "defense_evasion", "credential_access", "discovery", "lateral_movement",
        "collection", "exfiltration", "impact", "unknown",
    ]

    def generate(
        self,
        events: list[NormalizedEvent],
        alerts: list[Alert],
        investigation_id: str,
    ) -> dict[str, Any]:
        if not events:
            return {
                "investigation_id": investigation_id,
                "title": "No attack story available",
                "summary": "No events have been ingested for this investigation.",
                "chapters": [],
                "total_chapters": 0,
            }

        # Group events by phase
        by_phase: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in sorted(events, key=lambda e: e.timestamp):
            phase = str(event.attack_phase or "unknown")
            by_phase[phase].append(event)

        # Group alerts by phase
        alerts_by_phase: dict[str, list[str]] = defaultdict(list)
        for alert in alerts:
            alerts_by_phase[str(alert.phase)].append(alert.title)

        chapters: list[StoryChapter] = []
        step = 1
        for phase_key in self.PHASE_ORDER:
            phase_events = by_phase.get(phase_key, [])
            if not phase_events:
                continue

            headline = self._build_headline(phase_key, phase_events)
            narrative = self._build_narrative(phase_key, phase_events)
            key_events = [
                {
                    "event_id": e.event_id,
                    "title": e.title,
                    "timestamp": e.timestamp.isoformat(),
                    "host": e.host,
                    "user": e.user,
                    "severity": str(e.severity),
                }
                for e in phase_events[:5]
            ]

            chapters.append(
                StoryChapter(
                    step=step,
                    phase=phase_key,
                    headline=headline,
                    narrative=narrative,
                    events=key_events,
                    alerts=alerts_by_phase.get(phase_key, []),
                    timestamp_start=phase_events[0].timestamp.isoformat(),
                    timestamp_end=phase_events[-1].timestamp.isoformat(),
                )
            )
            step += 1

        summary = self._build_summary(chapters, events, alerts)

        return {
            "investigation_id": investigation_id,
            "title": f"Attack Story — {len(chapters)} phases detected",
            "summary": summary,
            "chapters": [c.to_dict() for c in chapters],
            "total_chapters": len(chapters),
        }

    def _build_headline(self, phase: str, events: list[NormalizedEvent]) -> str:
        label = PHASE_LABELS.get(phase, phase.replace("_", " ").title())
        hosts = list({e.host for e in events if e.host})
        users = list({e.user for e in events if e.user})

        if phase == "initial_access":
            user_str = f" by {users[0]}" if users else ""
            host_str = f" on {hosts[0]}" if hosts else ""
            return f"Attacker gained initial foothold{user_str}{host_str}"
        if phase == "execution":
            images = [
                e.process.image.rsplit("\\", 1)[-1]
                for e in events if e.process and e.process.image
            ]
            if images:
                return f"Malicious code executed via {images[0]}"
            return "Malicious code executed on compromised host"
        if phase == "credential_access":
            return "Credentials harvested from memory or registry"
        if phase == "lateral_movement":
            target_hosts = [e.network.dst_ip for e in events if e.network and e.network.dst_ip]
            if target_hosts:
                return f"Attacker moved laterally to {target_hosts[0]}"
            return f"Attacker spread to {len(hosts)} additional host(s)"
        if phase == "exfiltration":
            domains = [e.network.domain for e in events if e.network and e.network.domain]
            if domains:
                return f"Data exfiltrated to {domains[0]}"
            return "Sensitive data transferred to external destination"
        return f"{label} — {len(events)} event(s) observed"

    def _build_narrative(self, phase: str, events: list[NormalizedEvent]) -> str:
        base = PHASE_DESCRIPTIONS.get(phase, "")
        details: list[str] = []

        if phase == "initial_access":
            for e in events[:2]:
                if e.process and e.process.parent_image:
                    parent = e.process.parent_image.rsplit("\\", 1)[-1]
                    details.append(f"{parent} was used as the delivery mechanism")
                    break

        elif phase == "execution":
            for e in events[:3]:
                if e.process and e.process.command_line:
                    cmd = e.process.command_line[:80]
                    details.append(f'Command observed: "{cmd}…"')
                    break

        elif phase == "credential_access":
            for e in events[:3]:
                if e.process and e.process.image:
                    img = e.process.image.rsplit("\\", 1)[-1]
                    details.append(f"{img} was used to access credential stores")
                    break

        elif phase == "lateral_movement":
            dst_ips = list({e.network.dst_ip for e in events if e.network and e.network.dst_ip})
            if dst_ips:
                details.append(f"Target systems: {', '.join(dst_ips[:3])}")
            ports = list({e.network.dst_port for e in events if e.network and e.network.dst_port})
            if ports:
                port_names = {445: "SMB", 5985: "WinRM", 135: "RPC", 3389: "RDP"}
                named = [port_names.get(p, str(p)) for p in ports[:3]]
                details.append(f"Protocols used: {', '.join(named)}")

        elif phase == "exfiltration":
            total_bytes = sum(
                (e.network.bytes_sent or 0) for e in events if e.network
            )
            if total_bytes > 0:
                mb = total_bytes / (1024 * 1024)
                details.append(f"Approximately {mb:.1f} MB transferred outbound")
            domains = list({e.network.domain for e in events if e.network and e.network.domain})
            if domains:
                details.append(f"Destination: {domains[0]}")

        detail_str = " ".join(details)
        return f"{base} {detail_str}".strip()

    @staticmethod
    def _build_summary(
        chapters: list[StoryChapter],
        events: list[NormalizedEvent],
        alerts: list[Alert],
    ) -> str:
        phase_names = [PHASE_LABELS.get(c.phase, c.phase) for c in chapters]
        hosts = list({e.host for e in events if e.host})
        users = list({e.user for e in events if e.user})
        critical_alerts = [a for a in alerts if str(a.severity) == "critical"]

        parts = [
            f"This investigation covers {len(events)} events across {len(chapters)} attack phases: "
            f"{', '.join(phase_names)}."
        ]
        if users:
            parts.append(f"Primary account involved: {users[0]}.")
        if hosts:
            parts.append(f"Affected hosts: {', '.join(hosts[:4])}.")
        if critical_alerts:
            parts.append(
                f"{len(critical_alerts)} critical alert(s) were generated, "
                f"including: {critical_alerts[0].title}."
            )
        return " ".join(parts)
