from __future__ import annotations

from backend.app.models.enums import AttackPhase, SeverityLevel
from backend.app.schemas.alerts import Alert


class RiskScoringService:
    """Apply weighted risk scoring across alert context and analytic confidence."""

    SEVERITY_WEIGHTS = {
        SeverityLevel.INFO: 10.0,
        SeverityLevel.LOW: 25.0,
        SeverityLevel.MEDIUM: 50.0,
        SeverityLevel.HIGH: 75.0,
        SeverityLevel.CRITICAL: 90.0,
    }

    PHASE_WEIGHTS = {
        AttackPhase.INITIAL_ACCESS: 10.0,
        AttackPhase.EXECUTION: 15.0,
        AttackPhase.PERSISTENCE: 18.0,
        AttackPhase.PRIVILEGE_ESCALATION: 22.0,
        AttackPhase.DEFENSE_EVASION: 20.0,
        AttackPhase.CREDENTIAL_ACCESS: 28.0,
        AttackPhase.DISCOVERY: 12.0,
        AttackPhase.LATERAL_MOVEMENT: 26.0,
        AttackPhase.COLLECTION: 14.0,
        AttackPhase.EXFILTRATION: 30.0,
        AttackPhase.IMPACT: 24.0,
        AttackPhase.UNKNOWN: 8.0,
    }

    def calculate_score(
        self,
        severity: SeverityLevel,
        phase: AttackPhase,
        confidence: float,
        host_criticality: float = 1.0,
        anomaly_score: float = 0.0,
    ) -> float:
        base = self.SEVERITY_WEIGHTS.get(severity, 20.0)
        phase_weight = self.PHASE_WEIGHTS.get(phase, 10.0)
        confidence_weight = max(0.0, min(confidence, 1.0)) * 20.0
        criticality_weight = max(0.5, min(host_criticality, 2.0)) * 8.0
        anomaly_weight = max(0.0, min(anomaly_score, 1.0)) * 12.0
        return min(base + phase_weight + confidence_weight + criticality_weight + anomaly_weight, 100.0)

    def score_alert(
        self,
        alert: Alert,
        host_criticality: float = 1.0,
        anomaly_score: float = 0.0,
    ) -> Alert:
        alert.risk_score = self.calculate_score(
            severity=alert.severity,
            phase=alert.phase,
            confidence=alert.confidence,
            host_criticality=host_criticality,
            anomaly_score=anomaly_score,
        )
        return alert