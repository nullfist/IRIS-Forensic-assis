from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from backend.app.bootstrap import get_ingestion_service
from backend.app.models.enums import EventSource
from backend.app.parsers.file_upload_parser import EvidenceFileParser
from backend.app.schemas.ingestion import (
    IngestArtifact,
    IngestJobResponse,
    IngestJobStatusResponse,
    IngestRequest,
)
from backend.app.services.ingestion_service import IngestionService

router = APIRouter(prefix="/ingest", tags=["ingest"])

_file_parser = EvidenceFileParser()

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB


@router.post("", response_model=IngestJobResponse)
def submit_ingestion(
    request: IngestRequest,
    ingestion_service: IngestionService = Depends(get_ingestion_service),
) -> IngestJobResponse:
    return ingestion_service.submit_ingestion(request)


@router.post("/upload", response_model=IngestJobResponse)
async def upload_evidence_file(
    file: UploadFile = File(...),
    investigation_id: str = Form(default=""),
    ingestion_service: IngestionService = Depends(get_ingestion_service),
) -> IngestJobResponse:
    """
    Accept any digital evidence file, auto-detect its type, parse it into
    normalized records, run detection, and build the attack graph.

    Supported formats:
    - Sysmon JSON / JSONL
    - Windows Event Log JSON export (EVTX-exported)
    - PCAP flow metadata JSON
    - Windows XML event log (wevtutil export)
    - CSV logs
    - Disk image manifests (E01, DD, IMG, VMDK)
    - Memory dumps (DMP, MEM)
    - Generic text logs
    """
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum upload size of {MAX_UPLOAD_BYTES // (1024*1024)} MB.",
        )

    filename = file.filename or "unknown"
    detected_source, records = _file_parser.parse(filename, content)

    if detected_source == EventSource.UNKNOWN or not records:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Could not parse '{filename}'. "
                "Supported: .jsonl, .json, .evtx (JSON export), .xml, .csv, .pcap, "
                ".e01, .dd, .img, .vmdk, .dmp, .mem, .log, .txt"
            ),
        )

    inv_id = investigation_id.strip() or str(uuid.uuid4())

    artifact = IngestArtifact(
        source=detected_source,
        artifact_name=filename,
        records=records,
        metadata={"original_filename": filename, "detected_source": str(detected_source)},
    )
    request = IngestRequest(
        investigation_id=inv_id,
        artifacts=[artifact],
        enrich_graph=True,
    )
    result = ingestion_service.submit_ingestion(request)
    # Expose investigation_id in the response so the frontend can adopt it
    return IngestJobResponse(
        job_id=result.job_id,
        investigation_id=inv_id,
        status=result.status,
        submitted_at=result.submitted_at,
        artifact_count=result.artifact_count,
        message=(
            f"[{str(detected_source).upper()}] {filename} → "
            f"{result.message}"
        ),
    )


@router.get("/jobs/{job_id}", response_model=IngestJobStatusResponse)
def get_ingestion_job_status(
    job_id: str,
    ingestion_service: IngestionService = Depends(get_ingestion_service),
) -> IngestJobStatusResponse:
    return ingestion_service.get_job_status(job_id)
