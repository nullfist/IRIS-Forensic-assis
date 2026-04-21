from __future__ import annotations

from collections import defaultdict
from threading import Lock
from typing import Any

from backend.app.schemas.alerts import Alert
from backend.app.schemas.events import NormalizedEvent
from backend.app.schemas.ingestion import Case, IngestJobStatusResponse


class MemoryStore:
    """Thread-safe in-memory repository for local development and tests."""

    def __init__(self) -> None:
        self._lock = Lock()
        self.jobs: dict[str, IngestJobStatusResponse] = {}
        self.events_by_investigation: dict[str, list[NormalizedEvent]] = defaultdict(list)
        self.alerts_by_investigation: dict[str, list[Alert]] = defaultdict(list)
        self.metadata: dict[str, dict[str, Any]] = defaultdict(dict)
        self.cases: dict[str, Case] = {}  # case_id -> Case

    def upsert_job(self, job: IngestJobStatusResponse) -> None:
        with self._lock:
            self.jobs[job.job_id] = job

    def get_job(self, job_id: str) -> IngestJobStatusResponse | None:
        return self.jobs.get(job_id)

    def add_events(self, investigation_id: str, events: list[NormalizedEvent]) -> None:
        with self._lock:
            self.events_by_investigation[investigation_id].extend(events)

    def set_alerts(self, investigation_id: str, alerts: list[Alert]) -> None:
        with self._lock:
            self.alerts_by_investigation[investigation_id] = alerts

    def append_alerts(self, investigation_id: str, alerts: list[Alert]) -> None:
        with self._lock:
            self.alerts_by_investigation[investigation_id].extend(alerts)

    def get_events(self, investigation_id: str | None = None) -> list[NormalizedEvent]:
        if investigation_id:
            return list(self.events_by_investigation.get(investigation_id, []))
        result: list[NormalizedEvent] = []
        for events in self.events_by_investigation.values():
            result.extend(events)
        return result

    def get_alerts(self, investigation_id: str | None = None) -> list[Alert]:
        if investigation_id:
            return list(self.alerts_by_investigation.get(investigation_id, []))
        result: list[Alert] = []
        for alerts in self.alerts_by_investigation.values():
            result.extend(alerts)
        return result

    def get_alert(self, alert_id: str) -> Alert | None:
        for alerts in self.alerts_by_investigation.values():
            for alert in alerts:
                if alert.alert_id == alert_id:
                    return alert
        return None

    # ── Case management ──────────────────────────────────────────────

    def upsert_case(self, case: Case) -> None:
        with self._lock:
            self.cases[case.case_id] = case

    def get_case(self, case_id: str) -> Case | None:
        return self.cases.get(case_id)

    def get_all_cases(self) -> list[Case]:
        cases = list(self.cases.values())
        # Enrich with live event/alert counts
        for case in cases:
            case.event_count = len(self.events_by_investigation.get(case.investigation_id, []))
            case.alert_count = len(self.alerts_by_investigation.get(case.investigation_id, []))
        return sorted(cases, key=lambda c: c.created_at, reverse=True)

    def delete_case(self, case_id: str) -> bool:
        with self._lock:
            if case_id in self.cases:
                del self.cases[case_id]
                return True
            return False


_STORE: MemoryStore | None = None


def get_memory_store() -> MemoryStore:
    global _STORE
    if _STORE is None:
        _STORE = MemoryStore()
    return _STORE