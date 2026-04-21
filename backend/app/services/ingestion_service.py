from __future__ import annotations

import uuid
from datetime import datetime, timezone

from backend.app.graph.graph_service import GraphService
from backend.app.repository.memory_store import MemoryStore
from backend.app.schemas.ingestion import IngestJobResponse, IngestJobStatusResponse, IngestRequest
from backend.app.services.detection_service import DetectionService
from backend.app.services.normalization_service import NormalizationService


class IngestionService:
    """Submit and track ingestion jobs using pluggable repository-backed services."""

    def __init__(
        self,
        store: MemoryStore,
        normalization_service: NormalizationService,
        detection_service: DetectionService,
        graph_service: GraphService,
    ) -> None:
        self.store = store
        self.normalization_service = normalization_service
        self.detection_service = detection_service
        self.graph_service = graph_service

    def submit_ingestion(self, request: IngestRequest) -> IngestJobResponse:
        job_id = str(uuid.uuid4())
        submitted_at = datetime.now(timezone.utc)
        job = IngestJobStatusResponse(
            job_id=job_id,
            investigation_id=request.investigation_id,
            status="processing",
            submitted_at=submitted_at,
            processed_artifacts=0,
            normalized_events=0,
            generated_alerts=0,
        )
        self.store.upsert_job(job)

        all_events = []
        for artifact in request.artifacts:
            normalized_events = self.normalization_service.normalize(
                source=artifact.source,
                records=artifact.records,
                investigation_id=request.investigation_id,
                artifact_name=artifact.artifact_name,
            )
            self.store.add_events(request.investigation_id, normalized_events)
            all_events.extend(normalized_events)
            job.processed_artifacts += 1
            job.normalized_events += len(normalized_events)

        alerts = self.detection_service.build_alerts(all_events)
        self.store.set_alerts(request.investigation_id, alerts)
        job.generated_alerts = len(alerts)

        if request.enrich_graph and all_events:
            self.graph_service.build_graph(all_events)

        job.status = "completed"
        job.completed_at = datetime.now(timezone.utc)
        self.store.upsert_job(job)

        return IngestJobResponse(
            job_id=job_id,
            investigation_id=request.investigation_id,
            status=job.status,
            submitted_at=submitted_at,
            artifact_count=len(request.artifacts),
            message=f"Ingestion completed with {job.normalized_events} normalized events.",
        )

    def get_job_status(self, job_id: str) -> IngestJobStatusResponse:
        job = self.store.get_job(job_id)
        if job is None:
            return IngestJobStatusResponse(
                job_id=job_id,
                investigation_id="unknown",
                status="not_found",
                submitted_at=datetime.now(timezone.utc),
                error="Job ID not found.",
            )
        return job