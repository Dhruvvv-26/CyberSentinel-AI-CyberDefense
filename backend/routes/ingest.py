"""
CyberSentinel – Log Ingestion Route
POST /api/ingest – Full pipeline: parse → predict → context → score → respond
"""

from fastapi import APIRouter, Request
from backend.models.schemas import LogEntry, IngestResponse

router = APIRouter()


@router.post("/api/ingest", response_model=IngestResponse)
async def ingest_log(log_entry: LogEntry, request: Request):
    """
    Ingest a single log entry through the full AI pipeline.
    Returns anomaly status, severity, and any alert generated.
    """
    pipeline = request.app.state.pipeline

    result = await pipeline.process_log(log_entry.model_dump())

    return IngestResponse(
        status="ok",
        is_anomaly=result.get("is_anomaly", False),
        severity=result.get("severity", "NORMAL"),
        threat_score=result.get("threat_score", 0),
        alert_id=result.get("alert_id"),
        suppressed=result.get("suppressed", False),
    )
