from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from backend.app.detection.anomaly_detector import AnomalyDetector
from backend.app.detection.rule_loader import RuleLoader
from backend.app.models.enums import AlertStatus, AttackPhase, SeverityLevel
from backend.app.schemas.alerts import Alert, AlertEvidence
from backend.app.schemas.events import NormalizedEvent
from backend.app.services.correlation_service import CorrelationService
from backend.app.services.risk_scoring_service import RiskScoringService


class DetectionService:
    """Run rule-based and anomaly-driven detections and materialize alerts."""

    def __init__(
        self,
        rule_loader: RuleLoader | None = None,
        anomaly_detector: AnomalyDetector | None = None,
        correlation_service: CorrelationService | None = None,
        risk_scoring_service: RiskScoringService | None = None,
    ) -> None:
        self.rule_loader = rule_loader or RuleLoader()
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        self.correlation_service = correlation_service or CorrelationService()
        self.risk_scoring_service = risk_scoring_service or RiskScoringService()

    def run_rules(self, events: list[NormalizedEvent]) -> list[dict[str, Any]]:
        rules = self.rule_loader.load_rules()
        matches: list[dict[str, Any]] = []
        matches.extend(self._detect_suspicious_process_chains(events))
        matches.extend(self._detect_credential_dumping(events))
        matches.extend(self._detect_lateral_movement(events))

        for pack_name, pack_rules in rules.items():
            for rule in pack_rules:
                family = rule.get("family") or pack_name
                title = rule.get("title") or rule.get("name") or family
                required_terms = [term.lower() for term in rule.get("match_any", [])]
                if not required_terms:
                    continue
                matched_events = []
                for event in events:
                    haystack = " ".join(
                        filter(
                            None,
                            [
                                event.title,
                                event.description,
                                event.process.image if event.process else None,
                                event.process.command_line if event.process else None,
                                str(event.raw_data),
                            ],
                        )
                    ).lower()
                    if any(term in haystack for term in required_terms):
                        matched_events.append(event)
                if matched_events:
                    matches.append(
                        {
                            "family": family,
                            "title": title,
                            "summary": rule.get("description") or f"Rule pack {pack_name} matched suspicious telemetry.",
                            "severity": rule.get("severity", "medium"),
                            "phase": rule.get("phase", "execution"),
                            "confidence": float(rule.get("confidence", 0.72)),
                            "events": matched_events,
                            "tactics": rule.get("attack_tactics", []),
                            "tags": [pack_name, "rule-pack"],
                        }
                    )
        return matches

    def run_anomaly_detection(self, events: list[NormalizedEvent]) -> dict[str, float]:
        return self.anomaly_detector.score_events(events)

    def build_alerts(self, events: list[NormalizedEvent]) -> list[Alert]:
        if not events:
            return []

        anomaly_scores = self.run_anomaly_detection(events)
        detections = self.run_rules(events)
        alerts: list[Alert] = []
        now = datetime.now(timezone.utc)

        for detection in detections:
            matched_events: list[NormalizedEvent] = detection["events"]
            primary = matched_events[0]
            confidence = max(detection.get("confidence", 0.75), max(anomaly_scores.get(event.event_id, 0.0) for event in matched_events))
            alert = Alert(
                alert_id=str(uuid.uuid4()),
                investigation_id=primary.investigation_id,
                family=detection["family"],
                title=detection["title"],
                summary=detection["summary"],
                severity=self._normalize_severity(detection.get("severity"), primary.severity),
                phase=self._normalize_phase(detection.get("phase"), primary.attack_phase),
                status=AlertStatus.NEW,
                confidence=min(confidence, 1.0),
                host=primary.host,
                user=primary.user,
                source_event_ids=[event.event_id for event in matched_events],
                evidence=[
                    AlertEvidence(
                        event_id=event.event_id,
                        entity_id=event.entities[0].entity_id if event.entities else None,
                        summary=event.title,
                        confidence=min(event.confidence, 1.0),
                        details={"event_type": event.event_type, "host": event.host, "user": event.user},
                    )
                    for event in matched_events[:10]
                ],
                # Filter out non-string entries (e.g. {Technique: T1003.001} dicts from YAML)
                tactics=[t for t in detection.get("tactics", []) if isinstance(t, str)],
                tags=detection.get("tags", []),
                created_at=now,
                updated_at=now,
            )
            anomaly_score = max(anomaly_scores.get(event.event_id, 0.0) for event in matched_events)
            alerts.append(self.risk_scoring_service.score_alert(alert, anomaly_score=anomaly_score))

        return self._deduplicate_alerts(alerts)

    def _detect_suspicious_process_chains(self, events: list[NormalizedEvent]) -> list[dict[str, Any]]:
        chains = self.correlation_service.process_chains(events)
        matches: list[dict[str, Any]] = []
        for chain in chains:
            images = " ".join(
                (event.process.image or "") + " " + (event.process.command_line or "")
                for event in chain
                if event.process
            ).lower()
            if "winword" in images and any(token in images for token in ("powershell", "wscript", "cscript", "cmd.exe", "rundll32")):
                matches.append(
                    {
                        "family": "suspicious_process_chain",
                        "title": "Suspicious Office child process chain",
                        "summary": "Office-spawned scripting or LOLBin execution suggests malicious document activity.",
                        "severity": "high",
                        "phase": "execution",
                        "confidence": 0.88,
                        "events": chain,
                        "tactics": ["Execution", "Defense Evasion"],
                        "tags": ["office", "lolbin", "process-chain"],
                    }
                )
        return matches

    def _detect_credential_dumping(self, events: list[NormalizedEvent]) -> list[dict[str, Any]]:
        indicators = self.correlation_service.credential_dumping_indicators(events)
        if not indicators:
            return []
        return [
            {
                "family": "credential_dumping",
                "title": "Credential dumping indicators detected",
                "summary": "Processes and command lines associated with LSASS access or memory dumping were observed.",
                "severity": "critical",
                "phase": "credential_access",
                "confidence": 0.93,
                "events": indicators,
                "tactics": ["Credential Access"],
                "tags": ["lsass", "memory-dump"],
            }
        ]

    def _detect_lateral_movement(self, events: list[NormalizedEvent]) -> list[dict[str, Any]]:
        groups = self.correlation_service.lateral_movement_groups(events)
        matches: list[dict[str, Any]] = []
        for host, grouped_events in groups.items():
            if len(grouped_events) >= 2:
                matches.append(
                    {
                        "family": "lateral_movement",
                        "title": f"Lateral movement activity grouped on {host}",
                        "summary": "Remote administration ports, service creation, or credential reuse patterns indicate lateral movement.",
                        "severity": "high",
                        "phase": "lateral_movement",
                        "confidence": 0.86,
                        "events": grouped_events,
                        "tactics": ["Lateral Movement", "Execution"],
                        "tags": ["smb", "winrm", "remote-service"],
                    }
                )
        return matches

    @staticmethod
    def _normalize_severity(value: Any, fallback: SeverityLevel) -> SeverityLevel:
        if not value:
            return fallback
        if isinstance(value, SeverityLevel):
            return value
        try:
            return SeverityLevel(str(value).lower())
        except ValueError:
            return fallback

    @staticmethod
    def _normalize_phase(value: Any, fallback: AttackPhase | None) -> AttackPhase:
        if not value:
            return fallback or AttackPhase.UNKNOWN
        if isinstance(value, AttackPhase):
            return value
        try:
            return AttackPhase(str(value).lower())
        except ValueError:
            return fallback or AttackPhase.UNKNOWN

    @staticmethod
    def _deduplicate_alerts(alerts: list[Alert]) -> list[Alert]:
        grouped: dict[tuple[str, tuple[str, ...]], Alert] = {}
        for alert in alerts:
            key = (alert.family, tuple(sorted(alert.source_event_ids)))
            if key not in grouped or grouped[key].risk_score < alert.risk_score:
                grouped[key] = alert
        return sorted(grouped.values(), key=lambda item: (item.risk_score, item.created_at), reverse=True)