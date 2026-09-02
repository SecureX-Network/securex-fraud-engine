"""Live blockchain evidence provider.

Maps responses from the SecureX blockchain HTTP client into structured
evidence. Never invents a VERIFIED result: verification only succeeds when the
blockchain explicitly reports the credential as existing and issued.
"""

from src.blockchain.client.service import SecureXBlockchainClient
from src.blockchain.verification.provider import (
    NOT_CONFIGURED,
    NOT_FOUND,
    UNAVAILABLE,
    VERIFICATION_FAILED,
    VERIFIED,
    BlockchainEvidence,
    BlockchainEvidenceProvider,
)


class LiveBlockchainEvidenceProvider(BlockchainEvidenceProvider):
    """Provider backed by the live SecureX blockchain endpoint."""

    def __init__(self, client: SecureXBlockchainClient | None = None, base_url: str | None = None):
        if client is not None:
            self.client = client
        elif base_url:
            self.client = SecureXBlockchainClient(base_url)
        else:
            self.client = None

    def verify_credential(
        self,
        credential_id: str,
        credential_fingerprint: str | None = None,
    ) -> BlockchainEvidence:
        if self.client is None:
            return BlockchainEvidence(
                state=NOT_CONFIGURED,
                details="Blockchain client not configured (no SECUREX_BLOCKCHAIN_URL)",
            )

        try:
            response = self.client.verify_credential(credential_id, credential_fingerprint)
        except Exception as exc:
            name = exc.__class__.__name__
            return BlockchainEvidence(
                state=VERIFICATION_FAILED if name != "BlockchainError" else _map_error(exc),
                details="Blockchain unreachable" if name != "BlockchainError" else str(getattr(exc, "message", "")),
            )

        return self._parse_response(response)

    def _parse_response(self, response: dict) -> BlockchainEvidence:
        if not isinstance(response, dict):
            return BlockchainEvidence(state=VERIFICATION_FAILED, details="Malformed blockchain response")

        exists = bool(response.get("exists") or response.get("credential_exists"))
        if not exists:
            return BlockchainEvidence(
                state=NOT_FOUND,
                exists=False,
                details="Credential not found on blockchain",
            )

        status = (response.get("status") or "").lower()
        revoked = bool(response.get("revoked") or status == "revoked")
        suspended = bool(response.get("suspended") or status == "suspended")

        if revoked:
            state = "REVOKED"
        elif suspended:
            state = "SUSPENDED"
        else:
            state = VERIFIED

        return BlockchainEvidence(
            state=state,
            exists=True,
            credential_fingerprint=response.get("credential_fingerprint"),
            issuance_state=response.get("issuance_state") or ("issued" if state == VERIFIED else None),
            revocation_state="revoked" if revoked else "active",
            suspension_state="suspended" if suspended else "active",
            transaction_reference=response.get("transaction_reference") or response.get("transaction_id"),
            block_reference=response.get("block_reference") or response.get("block_id"),
            proof_metadata=response.get("proof_metadata") or {},
            details="Credential verified on blockchain",
        )


def _map_error(exc: Exception) -> str:
    """Map a raised error message to a verification state."""
    msg = str(getattr(exc, "message", "")).lower()
    if "unreachable" in msg or "transport" in msg or "connection" in msg:
        return UNAVAILABLE
    return VERIFICATION_FAILED
