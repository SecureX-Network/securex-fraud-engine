"""V2 fingerprint endpoints.

Supports SHA-256/384/512 on raw bytes or structured data with deterministic
output and constant-time verification.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from src.api.v2.deps import require_auth
from src.fingerprint.service import FingerprintService, _validate_algorithm

router = APIRouter()

VALID_ALGORITHMS = ["sha256", "sha384", "sha512"]


class FingerprintCreateRequest(BaseModel):
    kind: str = Field(default="document", description="document|credential|analysis")
    data: str | None = Field(None, description="Base64-encoded bytes to fingerprint")
    structured: dict[str, Any] | None = Field(None, description="Structured data to fingerprint")
    algorithm: str = Field(default="sha256", description="Hash algorithm")
    reference_id: str | None = None


class FingerprintCreateResponse(BaseModel):
    request_id: str
    reference_id: str
    fingerprint: str
    algorithm: str
    kind: str
    created_at: str


class FingerprintVerifyRequest(BaseModel):
    data: str | None = Field(None, description="Base64-encoded bytes to verify")
    structured: dict[str, Any] | None = Field(None, description="Structured data to verify")
    expected_fingerprint: str = Field(..., description="Expected fingerprint")
    algorithm: str = Field(default="sha256")


class FingerprintVerifyResponse(BaseModel):
    request_id: str
    reference_id: str
    is_valid: bool
    computed_fingerprint: str
    expected_fingerprint: str
    verified_at: str


def _decode(data: str | None) -> bytes | None:
    import base64

    if data is None:
        return None
    return base64.b64decode(data)


@router.post("/create", response_model=FingerprintCreateResponse, dependencies=[Depends(require_auth)])
async def create_fingerprint(request: FingerprintCreateRequest):
    _validate_algorithm(request.algorithm)
    service = FingerprintService()
    ref = request.reference_id or f"fp_{uuid4().hex}"

    if request.structured is not None:
        fingerprint = service.fingerprint_data(request.structured, request.algorithm)
    elif request.data is not None:
        fingerprint = service.fingerprint_bytes(_decode(request.data) or b"", request.algorithm)
    else:
        fingerprint = service.fingerprint_bytes(b"", request.algorithm)

    return FingerprintCreateResponse(
        request_id=str(uuid4()),
        reference_id=ref,
        fingerprint=fingerprint,
        algorithm=request.algorithm,
        kind=request.kind,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


@router.post("/verify", response_model=FingerprintVerifyResponse, dependencies=[Depends(require_auth)])
async def verify_fingerprint(request: FingerprintVerifyRequest):
    _validate_algorithm(request.algorithm)
    service = FingerprintService()
    ref = f"fp_{uuid4().hex}"

    if request.structured is not None:
        computed = service.fingerprint_data(request.structured, request.algorithm)
    else:
        computed = service.fingerprint_bytes(_decode(request.data) or b"", request.algorithm)

    is_valid = service._constant_time_compare(computed, request.expected_fingerprint)

    return FingerprintVerifyResponse(
        request_id=str(uuid4()),
        reference_id=ref,
        is_valid=is_valid,
        computed_fingerprint=computed,
        expected_fingerprint=request.expected_fingerprint,
        verified_at=datetime.now(timezone.utc).isoformat(),
    )
