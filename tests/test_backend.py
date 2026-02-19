"""
CyberSentinel – Backend API Tests
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["DEMO_MODE"] = "false"

from fastapi.testclient import TestClient
from backend.main import app, Pipeline


@pytest.fixture(autouse=True)
def setup_pipeline():
    """Initialize the pipeline on app.state before each test."""
    app.state.pipeline = Pipeline()
    yield


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app, raise_server_exceptions=True)


class TestAPIEndpoints:
    def test_root_returns_html_or_json(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_stats_endpoint(self, client):
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_logs" in data
        assert "total_alerts" in data

    def test_alerts_endpoint(self, client):
        response = client.get("/api/alerts")
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data

    def test_ingest_valid_log(self, client):
        log = {
            "timestamp": "2026-02-19T12:00:00+00:00",
            "src_ip": "10.0.0.50",
            "dst_ip": "203.0.113.50",
            "src_port": 50000,
            "dst_port": 443,
            "protocol": "TCP",
            "bytes_sent": 500,
            "bytes_recv": 1200,
            "duration": 0.5,
            "event_type": "connection",
            "log_level": "INFO",
            "message": "Normal connection established",
        }
        response = client.post("/api/ingest", json=log)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "is_anomaly" in data
        assert "severity" in data

    def test_ingest_invalid_log_returns_422(self, client):
        response = client.post("/api/ingest", json={"bad": "data"})
        assert response.status_code == 422

    def test_websocket_connection(self, client):
        with client.websocket_connect("/ws") as ws:
            data = ws.receive_json()
            assert data["type"] == "stats"
            ws.send_text("ping")
            pong = ws.receive_text()
            assert pong == "pong"
