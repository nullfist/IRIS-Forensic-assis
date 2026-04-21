from __future__ import annotations

from collections import Counter

import numpy as np
from sklearn.ensemble import IsolationForest

from backend.app.models.enums import EventCategory, SeverityLevel
from backend.app.schemas.events import NormalizedEvent


class AnomalyDetector:
    """Deterministic unsupervised anomaly scoring for local investigations."""

    def __init__(self, random_state: int = 42, contamination: float = 0.15) -> None:
        self.random_state = random_state
        self.contamination = contamination

    def score_events(self, events: list[NormalizedEvent]) -> dict[str, float]:
        if not events:
            return {}

        features = self._build_feature_matrix(events)
        if len(events) < 4:
            return {event.event_id: self._fallback_score(event) for event in events}

        model = IsolationForest(
            n_estimators=100,
            contamination=min(self.contamination, max(0.01, 1.0 / len(events))),
            random_state=self.random_state,
        )
        model.fit(features)
        raw_scores = -model.score_samples(features)
        min_score = float(raw_scores.min())
        max_score = float(raw_scores.max())
        if max_score == min_score:
            return {event.event_id: 0.1 for event in events}

        normalized_scores = (raw_scores - min_score) / (max_score - min_score)
        return {event.event_id: float(score) for event, score in zip(events, normalized_scores, strict=False)}

    def _build_feature_matrix(self, events: list[NormalizedEvent]) -> np.ndarray:
        category_counts = Counter(event.category for event in events)
        severity_rank = {
            SeverityLevel.INFO: 0,
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4,
        }

        matrix: list[list[float]] = []
        for event in events:
            category_flag = 1.0 if event.category == EventCategory.NETWORK else 0.0
            command_length = float(len(event.process.command_line)) if event.process and event.process.command_line else 0.0
            distinctiveness = 1.0 / max(category_counts[event.category], 1)
            network_bytes = float(
                (event.network.bytes_sent or 0) + (event.network.bytes_received or 0)
            ) if event.network else 0.0
            features = [
                float(severity_rank.get(event.severity, 0)),
                category_flag,
                command_length,
                network_bytes,
                float(len(event.entities)),
                distinctiveness,
            ]
            matrix.append(features)
        return np.array(matrix, dtype=float)

    @staticmethod
    def _fallback_score(event: NormalizedEvent) -> float:
        score = 0.05
        if event.severity in {SeverityLevel.HIGH, SeverityLevel.CRITICAL}:
            score += 0.35
        if event.process and event.process.command_line and "powershell" in event.process.command_line.lower():
            score += 0.2
        if event.network and (event.network.bytes_sent or 0) > 1_000_000:
            score += 0.25
        return min(score, 1.0)