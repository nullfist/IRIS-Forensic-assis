"""Reusable risk constants and helper functions for IRIS detections."""

from __future__ import annotations

from typing import Iterable

SEVERITY_WEIGHTS = {
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 45,
}

PHASE_WEIGHTS = {
    "initial_access": 8,
    "execution": 10,
    "persistence": 12,
    "privilege_escalation": 14,
    "defense_evasion": 16,
    "credential_access": 20,
    "discovery": 10,
    "lateral_movement": 18,
    "collection": 12,
    "command_and_control": 15,
    "exfiltration": 25,
}

HOST_CRITICALITY_WEIGHTS = {
    "low": 0.9,
    "medium": 1.0,
    "high": 1.15,
    "critical": 1.3,
}

ANOMALY_MULTIPLIER_RANGE = (0.85, 1.25)
MAX_RISK_SCORE = 100.0


def clamp_score(value: float, lower: float = 0.0, upper: float = MAX_RISK_SCORE) -> float:
    return max(lower, min(upper, round(value, 2)))


def weighted_average(values: Iterable[float], weights: Iterable[float]) -> float:
    values_list = list(values)
    weights_list = list(weights)
    if not values_list or not weights_list or len(values_list) != len(weights_list):
        return 0.0
    denominator = sum(weights_list)
    if denominator == 0:
        return 0.0
    return sum(v * w for v, w in zip(values_list, weights_list)) / denominator


def compute_risk_score(
    *,
    severity: str,
    phase: str,
    host_criticality: str = "medium",
    anomaly_score: float = 0.0,
    confidence: float = 1.0,
    evidence_count: int = 1,
) -> float:
    severity_component = SEVERITY_WEIGHTS.get(severity.lower(), 10)
    phase_component = PHASE_WEIGHTS.get(phase, 10)
    confidence_component = max(0.4, min(1.0, confidence))
    evidence_component = min(1.2, 0.85 + (0.05 * max(evidence_count, 1)))
    anomaly_multiplier = max(ANOMALY_MULTIPLIER_RANGE[0], min(ANOMALY_MULTIPLIER_RANGE[1], 1.0 + anomaly_score))
    criticality_multiplier = HOST_CRITICALITY_WEIGHTS.get(host_criticality, 1.0)
    raw = (severity_component + phase_component) * confidence_component * evidence_component * anomaly_multiplier * criticality_multiplier
    return clamp_score(raw)