"""
CyberSentinel – WebSocket Connection Manager
Manages active WebSocket connections and broadcasts messages to all clients.
"""

import json
from fastapi import WebSocket
from typing import Any


class ConnectionManager:
    """Track and broadcast to all active WebSocket clients."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"📡 WebSocket connected – {len(self.active_connections)} active clients")

    def disconnect(self, websocket: WebSocket):
        """Remove a disconnected WebSocket."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        print(f"📡 WebSocket disconnected – {len(self.active_connections)} active clients")

    async def broadcast_json(self, data: dict):
        """Send JSON data to all connected clients."""
        if not self.active_connections:
            return

        message = json.dumps(data, default=str)
        disconnected = []
        for conn in self.active_connections:
            try:
                await conn.send_text(message)
            except Exception:
                disconnected.append(conn)

        for conn in disconnected:
            self.disconnect(conn)

    async def broadcast_log(self, log: dict):
        """Broadcast a processed log entry."""
        await self.broadcast_json({"type": "log", "data": log})

    async def broadcast_alert(self, alert: dict):
        """Broadcast a new alert."""
        await self.broadcast_json({"type": "alert", "data": alert})

    async def broadcast_stats(self, stats: dict):
        """Broadcast updated dashboard statistics."""
        await self.broadcast_json({"type": "stats", "data": stats})

    @property
    def client_count(self) -> int:
        return len(self.active_connections)


# Singleton instance
manager = ConnectionManager()
