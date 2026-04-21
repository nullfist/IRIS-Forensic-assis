from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.app.models.enums import AttackPhase, SeverityLevel
from backend.app.schemas.events import NormalizedEvent


class RootCauseResult:
    def __init__(
        self,
        event_id: str,
        title: str,
        timestamp: datetime,
        host: str | None,
        user: str | None,
        confidence: float,
        reasoning: str,
        attack_chain: list[str],
        entry_entity_id: str | None,
    ) -> None:
        self.event_id = event_id
        self.title = title
        self.timestamp = timestamp
        self.host = host
        self.user = user
        self.confidence = confidence
        self.reasoning = reasoning
        self.attack_chain = attack_chain
        self.entry_entity_id = entry_entity_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "title": self.title,
            "timestamp": self.timestamp.isoformat(),
            "host": self.host,
            "user": self.user,
            "confidence": round(self.confidence, 2),
            "reasoning": self.reasoning,
            "attack_chain": self.attack_chain,
            "entry_entity_id": self.entry_entity_id,
        }


class RootCauseService:
    """
    Identify the most likely attack origin event from a set of normalized events.

    Strategy:
    1. Find the earliest event in the initial_access or execution phase
    2. Prefer events with Office/document parent processes (phishing indicators)
    3. Prefer events with external network connections as first touch
    4. Score confidence based on how many signals align
    """

    # Processes that strongly indicate user-initiated initial access
    INITIAL_ACCESS_IMAGES = {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe",
        "mshta.exe", "wscript.exe", "cscript.exe",
    }

    INITIAL_PHASE_ORDER = [
        AttackPhase.INITIAL_ACCESS,
        AttackPhase.EXECUTION,
        AttackPhase.PERSISTENCE,
        AttackPhase.PRIVILEGE_ESCALATION,
        AttackPhase.DEFENSE_EVASION,
        AttackPhase.CREDENTIAL_ACCESS,
        AttackPhase.DISCOVERY,
        AttackPhase.LATERAL_MOVEMENT,
        AttackPhase.COLLECTION,
        AttackPhase.EXFILTRATION,
        AttackPhase.IMPACT,
        AttackPhase.UNKNOWN,
    ]

    def identify(self, events: list[NormalizedEvent]) -> RootCauseResult | None:
        if not events:
            return None

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        candidates = self._score_candidates(sorted_events)
        if not candidates:
            return None

        best_event, confidence, reasoning_parts = max(candidates, key=lambda x: x[1])
        attack_chain = self._build_attack_chain(best_event, sorted_events)

        entry_entity_id = None
        if best_event.process and best_event.process.image:
            img = best_event.process.image.lower()
            entry_entity_id = f"process:{best_event.process.process_guid or img}"
        elif best_event.host:
            entry_entity_id = f"host:{best_event.host.lower()}"

        return RootCauseResult(
            event_id=best_event.event_id,
            title=best_event.title,
            timestamp=best_event.timestamp,
            host=best_event.host,
            user=best_event.user,
            confidence=min(confidence, 0.99),
            reasoning=reasoning_parts,
            attack_chain=attack_chain,
            entry_entity_id=entry_entity_id,
        )

    def _score_candidates(
        self, sorted_events: list[NormalizedEvent]
    ) -> list[tuple[NormalizedEvent, float, str]]:
        candidates: list[tuple[NormalizedEvent, float, str]] = []

        for event in sorted_events:
            score = 0.0
            reasons: list[str] = []

            # Phase scoring — earlier phases score higher
            phase = event.attack_phase or AttackPhase.UNKNOWN
            try:
                phase_idx = self.INITIAL_PHASE_ORDER.index(phase)
                phase_score = max(0.0, (len(self.INITIAL_PHASE_ORDER) - phase_idx) / len(self.INITIAL_PHASE_ORDER))
                score += phase_score * 0.35
                if phase in (AttackPhase.INITIAL_ACCESS, AttackPhase.EXECUTION):
                    reasons.append(f"Phase is {phase.replace('_', ' ')} (early kill-chain stage)")
            except ValueError:
                pass

            # Office/document parent process — strong phishing indicator
            if event.process:
                parent = (event.process.parent_image or "").lower()
                image = (event.process.image or "").lower()
                parent_name = parent.rsplit("\\", 1)[-1] if parent else ""
                image_name = image.rsplit("\\", 1)[-1] if image else ""

                if parent_name in self.INITIAL_ACCESS_IMAGES:
                    score += 0.30
                    reasons.append(f"Parent process is {parent_name} — typical phishing delivery vector")
                if image_name in self.INITIAL_ACCESS_IMAGES:
                    score += 0.20
                    reasons.append(f"Process image is {image_name} — user-initiated execution")

                # Encoded command — strong execution indicator
                cmd = (event.process.command_line or "").lower()
                if any(t in cmd for t in ("-enc", "-encodedcommand", "iex", "invoke-expression")):
                    score += 0.15
                    reasons.append("Encoded/obfuscated command line detected")

            # Severity boost
            if event.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL):
                score += 0.10
                reasons.append(f"Severity is {event.severity}")

            # Temporal boost — earlier events score higher
            if sorted_events:
                earliest = sorted_events[0].timestamp
                latest = sorted_events[-1].timestamp
                span = (latest - earliest).total_seconds() or 1
                age = (event.timestamp - earliest).total_seconds()
                temporal_score = max(0.0, 1.0 - (age / span)) * 0.10
                score += temporal_score

            if score > 0.15:
                reasoning_text = (
                    f"Attack likely started at '{event.title}' (confidence {min(score, 0.99):.0%}). "
                    + " ".join(reasons) + "."
                )
                candidates.append((event, score, reasoning_text))

        return candidates

    def _build_attack_chain(
        self, root: NormalizedEvent, all_events: list[NormalizedEvent]
    ) -> list[str]:
        """Build a high-level narrative chain from root event forward."""
        chain: list[str] = [f"[{root.timestamp.strftime('%H:%M:%S')}] {root.title}"]
        seen_phases: set[str] = {str(root.attack_phase)}

        for event in all_events:
            if event.event_id == root.event_id:
                continue
            phase_str = str(event.attack_phase)
            if phase_str not in seen_phases:
                seen_phases.add(phase_str)
                chain.append(
                    f"[{event.timestamp.strftime('%H:%M:%S')}] {event.title} "
                    f"({phase_str.replace('_', ' ')})"
                )
            if len(chain) >= 8:
                break

        return chain
