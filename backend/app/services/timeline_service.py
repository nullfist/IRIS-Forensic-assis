from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from backend.app.models.enums import AttackPhase
from backend.app.schemas.events import NormalizedEvent
from backend.app.schemas.timeline import ReplayFrame, ReplayResponse, TimelineEntry, TimelinePhaseGroup, TimelineResponse


class TimelineService:
    """Build analyst-facing timeline views from normalized events."""

    PHASE_ORDER: list[AttackPhase] = [
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

    def order_events(self, events: list[NormalizedEvent]) -> list[NormalizedEvent]:
        def sort_key(event: NormalizedEvent) -> tuple[datetime, datetime]:
            observed_at = event.observed_at or event.timestamp
            base_timestamp = event.timestamp or datetime.now(timezone.utc)
            return (base_timestamp, observed_at)

        return sorted(events, key=sort_key)

    def detect_phases(self, events: list[NormalizedEvent]) -> list[TimelinePhaseGroup]:
        ordered_events = self.order_events(events)
        grouped: dict[AttackPhase, list[NormalizedEvent]] = defaultdict(list)

        for event in ordered_events:
            phase = event.attack_phase or self._infer_phase(event)
            grouped[phase].append(event)

        phase_groups: list[TimelinePhaseGroup] = []
        for phase in self.PHASE_ORDER:
            phase_events = grouped.get(phase, [])
            if not phase_events:
                continue
            entries = [self._to_entry(event, idx) for idx, event in enumerate(phase_events)]
            phase_groups.append(
                TimelinePhaseGroup(
                    phase=phase,
                    started_at=phase_events[0].timestamp,
                    ended_at=phase_events[-1].timestamp,
                    start_time=phase_events[0].timestamp,
                    end_time=phase_events[-1].timestamp,
                    entries=entries,
                    event_count=len(phase_events),
                )
            )
        return phase_groups

    def build_timeline(self, investigation_id: str, events: list[NormalizedEvent]) -> TimelineResponse:
        ordered = self.order_events(events)
        entries = [self._to_entry(event, index) for index, event in enumerate(ordered)]
        return TimelineResponse(
            investigation_id=investigation_id,
            entries=entries,
            phases=self.detect_phases(ordered),
            total=len(entries),
        )

    def build_replay(
        self,
        investigation_id: str,
        events: list[NormalizedEvent],
        replay_position: int = 0,
    ) -> ReplayResponse:
        timeline = self.build_timeline(investigation_id, events)
        if not timeline.entries:
            frame = ReplayFrame(index=0, total=0)
            return ReplayResponse(investigation_id=investigation_id, replay_position=0, frame=frame)

        bounded_position = min(max(replay_position, 0), len(timeline.entries) - 1)
        current_entry = timeline.entries[bounded_position]
        start = max(bounded_position - 2, 0)
        end = min(bounded_position + 3, len(timeline.entries))
        frame = ReplayFrame(
            index=bounded_position,
            total=len(timeline.entries),
            current_timestamp=current_entry.timestamp,
            current_entry=current_entry,
            surrounding_entries=timeline.entries[start:end],
        )
        return ReplayResponse(
            investigation_id=investigation_id,
            replay_position=bounded_position,
            frame=frame,
        )

    def _to_entry(self, event: NormalizedEvent, index: int) -> TimelineEntry:
        phase = event.attack_phase or self._infer_phase(event)
        entry_id = f"timeline-{index}-{event.event_id}"
        return TimelineEntry(
            entry_id=entry_id,
            event_id=event.event_id,
            timestamp=event.timestamp,
            phase=phase,
            title=event.title,
            summary=event.description or event.event_type.replace("_", " "),
            severity=event.severity,
            source=str(event.source),
            event_ids=[event.event_id],
            host=event.host,
            user=event.user,
            events=[event],
        )

    @staticmethod
    def _infer_phase(event: NormalizedEvent) -> AttackPhase:
        event_type = event.event_type.lower()
        title = event.title.lower()
        if "logon" in event_type or "logon" in title:
            return AttackPhase.INITIAL_ACCESS
        if "powershell" in event_type or "process" in event_type:
            return AttackPhase.EXECUTION
        if "service_install" in event_type or "scheduled_task" in event_type or "registry" in event_type:
            return AttackPhase.PERSISTENCE
        if "credential" in title or "lsass" in title or "sekurlsa" in str(event.raw_data).lower():
            return AttackPhase.CREDENTIAL_ACCESS
        if "445" in str(event.raw_data) or "winrm" in str(event.raw_data).lower():
            return AttackPhase.LATERAL_MOVEMENT
        if event.network and (event.network.bytes_sent or 0) > 1_000_000:
            return AttackPhase.EXFILTRATION
        return AttackPhase.UNKNOWN