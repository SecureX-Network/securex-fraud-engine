"""Health Check Endpoints"""

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel

from src.core.version import APP_NAME, APP_VERSION

router = APIRouter()


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    timestamp: str
    version: str
    service: str


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc).isoformat(),
        version=APP_VERSION,
        service=APP_NAME,
    )


@router.get("/ready")
async def readiness_check():
    """Readiness check endpoint."""
    # TODO: Add database connectivity check if needed
    return {"status": "ready"}
