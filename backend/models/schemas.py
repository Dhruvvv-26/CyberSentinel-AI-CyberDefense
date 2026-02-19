"""
CyberSentinel – Pydantic Schemas
Data models for log entries, alerts, stats, and API responses.
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class LogEntry(BaseModel):
    """Incoming log entry from simulator or external source."""
    id: Optional[str] = None
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int | float
    bytes_recv: int | float
    duration: float
    event_type: str
    log_level: str
    message: str


class Alert(BaseModel):
    """Generated alert with severity and response actions."""
    id: str
    timestamp: str
    severity: str
    threat_score: int
    src_ip: str
    dst_ip: str
    event_type: str
    message: str
    anomaly_score: float
    confidence: float
    factors: dict = {}
    actions: list[dict] = []


class DashboardStats(BaseModel):
    """Real-time counters for the SOC dashboard."""
    total_logs: int = 0
    total_alerts: int = 0
    severity_counts: dict = Field(default_factory=lambda: {
        "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0,
    })
    active_threats: int = 0
    suppressed_count: int = 0
    model_loaded: bool = False


class ResponseAction(BaseModel):
    """A response action logged by the ResponseAgent."""
    timestamp: str
    alert_id: str
    action: str
    target: str
    severity: str


class IngestResponse(BaseModel):
    """API response after ingesting a log."""
    status: str = "ok"
    is_anomaly: bool = False
    severity: str = "NORMAL"
    threat_score: int = 0
    alert_id: Optional[str] = None
    suppressed: bool = False
