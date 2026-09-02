"""Fingerprint API Endpoints"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter
from pydantic import BaseModel, Field

from src.fingerprint.service import FingerprintService

router = APIRouter()


class FingerprintCreateRequest(BaseModel):
    """Request model for fingerprint creation."""

    credential_id: str = Field(..., description="Credential identifier")
    credential_data: dict[str, Any] = Field(..., description="Credential data to fingerprint")
    algorithm: str = Field(default="sha256", description="Hash algorithm to use")


class FingerprintCreateResponse(BaseModel):
    """Response model for fingerprint creation."""

    request_id: str
    credential_id: str
    fingerprint: str
    algorithm: str
    created_at: str


class FingerprintVerifyRequest(BaseModel):
    """Request model for fingerprint verification."""

    credential_id: str = Field(..., description="Credential identifier")
    credential_data: dict[str, Any] = Field(..., description="Credential data to verify")
    expected_fingerprint: str = Field(..., description="Expected fingerprint to compare against")
    algorithm: str = Field(default="sha256", description="Hash algorithm to use")


class FingerprintVerifyResponse(BaseModel):
    """Response model for fingerprint verification."""

    request_id: str
    credential_id: str
    is_valid: bool
    computed_fingerprint: str
    expected_fingerprint: str
    verified_at: str


@router.post("/create", response_model=FingerprintCreateResponse)
async def create_fingerprint(request: FingerprintCreateRequest):
    """Create a deterministic fingerprint for credential data."""
    service = FingerprintService()
    fingerprint = service.create(request.credential_data, request.algorithm)

    return FingerprintCreateResponse(
        request_id=str(uuid4()),
        credential_id=request.credential_id,
        fingerprint=fingerprint,
        algorithm=request.algorithm,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


@router.post("/verify", response_model=FingerprintVerifyResponse)
async def verify_fingerprint(request: FingerprintVerifyRequest):
    """Verify credential data against an expected fingerprint."""
    service = FingerprintService()
    is_valid = service.verify(
        request.credential_data,
        request.expected_fingerprint,
        request.algorithm,
    )
    computed = service.create(request.credential_data, request.algorithm)

    return FingerprintVerifyResponse(
        request_id=str(uuid4()),
        credential_id=request.credential_id,
        is_valid=is_valid,
        computed_fingerprint=computed,
        expected_fingerprint=request.expected_fingerprint,
        verified_at=datetime.now(timezone.utc).isoformat(),
    )
