"""
CyberSentinel – FastAPI Main Application
Orchestrates the full AI pipeline with WebSocket streaming and demo mode.
"""

import asyncio
import sys
import os

# Fix imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from config import HOST, PORT, LOG_LEVEL, DEMO_MODE, DEMO_LOG_INTERVAL, MAX_LOGS_STORED
from backend.ws.manager import manager
from backend.routes.ingest import router as ingest_router
from backend.routes.alerts import router as alerts_router
from ingestion.log_parser import parse_log
from ml.predict import AnomalyDetector
from ml.features import extract_features_single
from agents.context_agent import ContextAgent
from agents.threat_scorer import ThreatScorer
from agents.response_agent import ResponseAgent
from simulator.log_generator import generate_single_log


# ──────────────────── Pipeline Orchestrator ────────────────────

class Pipeline:
    """Orchestrates the full CyberSentinel processing pipeline."""

    def __init__(self):
        self.detector = AnomalyDetector()
        self.context_agent = ContextAgent()
        self.threat_scorer = ThreatScorer()
        self.response_agent = ResponseAgent()
        self.processed_logs: list[dict] = []
        self.total_logs = 0

    async def process_log(self, raw_log: dict) -> dict:
        """
        Full pipeline: parse → predict → context → score → respond → broadcast.
        """
        # 1. Parse and enrich
        parsed = parse_log(raw_log)
        if parsed is None:
            return {"error": "Invalid log entry"}

        self.total_logs += 1

        # Store log
        self.processed_logs.append(parsed)
        if len(self.processed_logs) > MAX_LOGS_STORED:
            self.processed_logs = self.processed_logs[-MAX_LOGS_STORED:]

        # 2. ML Anomaly Detection
        anomaly_result = self.detector.predict(parsed)

        # 3. Context Evaluation
        context_result = self.context_agent.evaluate(parsed, anomaly_result)

        # 4. Threat Scoring
        score_result = self.threat_scorer.score(parsed, anomaly_result, context_result)

        # 5. Response Actions
        alert = self.response_agent.respond(parsed, score_result, anomaly_result)

        # 6. Build broadcast payload
        log_payload = {
            "id": parsed.get("id", ""),
            "timestamp": parsed.get("timestamp_utc", parsed.get("timestamp", "")),
            "src_ip": parsed.get("src_ip", ""),
            "dst_ip": parsed.get("dst_ip", ""),
            "event_type": parsed.get("event_type", ""),
            "log_level": parsed.get("log_level", ""),
            "message": parsed.get("message", ""),
            "is_anomaly": anomaly_result.get("is_anomaly", False),
            "severity": score_result.get("severity", "NORMAL"),
            "threat_score": score_result.get("threat_score", 0),
        }

        # 7. Broadcast to WebSocket clients
        await manager.broadcast_log(log_payload)

        if alert:
            await manager.broadcast_alert(alert)

        # Broadcast updated stats
        await manager.broadcast_stats(self.get_stats())

        return {
            "is_anomaly": anomaly_result.get("is_anomaly", False),
            "severity": score_result.get("severity", "NORMAL"),
            "threat_score": score_result.get("threat_score", 0),
            "alert_id": alert["id"] if alert else None,
            "suppressed": context_result.get("suppress", False),
        }

    def get_stats(self) -> dict:
        """Get current pipeline statistics for the dashboard."""
        response_stats = self.response_agent.get_stats()
        context_stats = self.context_agent.get_stats()
        return {
            "total_logs": self.total_logs,
            "total_alerts": response_stats["total_alerts"],
            "severity_counts": response_stats.get("by_severity", {}),
            "active_threats": sum(
                v for k, v in response_stats.get("by_severity", {}).items()
                if k in ("HIGH", "CRITICAL")
            ),
            "suppressed_count": context_stats.get("suppressed", 0),
            "model_loaded": self.detector.is_loaded,
            "ws_clients": manager.client_count,
        }


# ──────────────────── Demo Mode Background Task ───────────────

async def demo_log_generator(pipeline: Pipeline):
    """Continuously generate and process synthetic logs for demo mode."""
    print(f"🔄 Demo mode active – generating logs every {DEMO_LOG_INTERVAL}s")
    while True:
        try:
            raw_log = generate_single_log()
            await pipeline.process_log(raw_log)
            await asyncio.sleep(DEMO_LOG_INTERVAL)
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"Demo generator error: {e}")
            await asyncio.sleep(2)


# ──────────────────── App Lifespan ─────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown logic."""
    # Startup
    pipeline = Pipeline()
    app.state.pipeline = pipeline

    print("=" * 60)
    print("  🛡️  CyberSentinel – AI-Driven Cyber Defense System")
    print("=" * 60)
    print(f"  Model loaded: {'✅' if pipeline.detector.is_loaded else '❌ Run: python -m ml.train'}")
    print(f"  Demo mode:    {'ON' if DEMO_MODE else 'OFF'}")
    print(f"  Dashboard:    http://{HOST}:{PORT}")
    print(f"  API docs:     http://{HOST}:{PORT}/docs")
    print("=" * 60)

    demo_task = None
    if DEMO_MODE and pipeline.detector.is_loaded:
        demo_task = asyncio.create_task(demo_log_generator(pipeline))

    yield

    # Shutdown
    if demo_task:
        demo_task.cancel()
        try:
            await demo_task
        except asyncio.CancelledError:
            pass
    print("🛑 CyberSentinel shutting down.")


# ──────────────────── FastAPI App ──────────────────────────────

app = FastAPI(
    title="CyberSentinel",
    description="AI-Driven Autonomous Cyber Defense System",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(ingest_router)
app.include_router(alerts_router)

# Static files (dashboard)
DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"
if DASHBOARD_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")


@app.get("/")
async def serve_dashboard():
    """Serve the SOC dashboard."""
    index_path = DASHBOARD_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "CyberSentinel API is running. Dashboard not found."}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time dashboard updates."""
    await manager.connect(websocket)
    try:
        # Send initial stats
        pipeline = app.state.pipeline
        await websocket.send_json({"type": "stats", "data": pipeline.get_stats()})

        # Keep connection alive
        while True:
            data = await websocket.receive_text()
            # Client can send ping/pong
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


# ──────────────────── CLI Entry Point ──────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=HOST,
        port=PORT,
        log_level=LOG_LEVEL,
        reload=False,
    )
