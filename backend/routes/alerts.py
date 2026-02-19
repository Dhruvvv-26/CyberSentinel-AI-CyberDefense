"""
CyberSentinel – Alerts & Stats Routes
GET /api/alerts – Recent alerts
GET /api/stats  – Dashboard statistics
"""

from fastapi import APIRouter, Request, Query

router = APIRouter()


@router.get("/api/alerts")
async def get_alerts(request: Request, limit: int = Query(50, ge=1, le=500)):
    """Get recent alerts, newest first."""
    pipeline = request.app.state.pipeline
    alerts = pipeline.response_agent.get_recent_alerts(limit)
    return {"alerts": list(reversed(alerts)), "total": len(alerts)}


@router.get("/api/stats")
async def get_stats(request: Request):
    """Get current dashboard statistics."""
    pipeline = request.app.state.pipeline
    return pipeline.get_stats()
