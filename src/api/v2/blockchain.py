"""V2 blockchain evidence verification endpoints."""

from uuid import uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from src.api.v2.deps import require_auth
from src.blockchain.adapter import build_blockchain_provider
from src.blockchain.verification.provider import BlockchainEvidenceProvider

router = APIRouter()


class BlockchainVerifyRequest(BaseModel):
    credential_id: str = Field(..., description="Credential identifier")
    credential_fingerprint: str | None = None


class BlockchainVerifyResponse(BaseModel):
    request_id: str
    credential_id: str
    state: str
    exists: bool
    credential_fingerprint: str | None = None
    issuance_state: str | None = None
    revocation_state: str | None = None
    suspension_state: str | None = None
    transaction_reference: str | None = None
    block_reference: str | None = None
    proof_metadata: dict = Field(default_factory=dict)
    details: str = ""


@router.post("/verify", response_model=BlockchainVerifyResponse, dependencies=[Depends(require_auth)])
async def verify_blockchain(
    request: BlockchainVerifyRequest,
    provider: BlockchainEvidenceProvider = Depends(lambda: build_blockchain_provider()),
):
    evidence = provider.verify_credential(request.credential_id, request.credential_fingerprint)
    return BlockchainVerifyResponse(
        request_id=str(uuid4()),
        credential_id=request.credential_id,
        state=evidence.state,
        exists=evidence.exists,
        credential_fingerprint=evidence.credential_fingerprint,
        issuance_state=evidence.issuance_state,
        revocation_state=evidence.revocation_state,
        suspension_state=evidence.suspension_state,
        transaction_reference=evidence.transaction_reference,
        block_reference=evidence.block_reference,
        proof_metadata=evidence.proof_metadata,
        details=evidence.details,
    )
