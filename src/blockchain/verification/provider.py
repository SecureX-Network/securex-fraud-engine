"""Blockchain evidence verification models and provider interface.

States reflect structured integration state so the engine remains testable
without a live blockchain and never fakes successful verification in
production code.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

UNAVAILABLE = "UNAVAILABLE"
NOT_CONFIGURED = "NOT_CONFIGURED"
VERIFICATION_FAILED = "VERIFICATION_FAILED"
VERIFIED = "VERIFIED"
NOT_FOUND = "NOT_FOUND"


@dataclass
class BlockchainEvidence:
    """Result of a blockchain evidence verification request."""

    state: str
    exists: bool = False
    credential_fingerprint: str | None = None
    issuance_state: str | None = None
    revocation_state: str | None = None
    suspension_state: str | None = None
    transaction_reference: str | None = None
    block_reference: str | None = None
    proof_metadata: dict[str, Any] = field(default_factory=dict)
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "exists": self.exists,
            "credential_fingerprint": self.credential_fingerprint,
            "issuance_state": self.issuance_state,
            "revocation_state": self.revocation_state,
            "suspension_state": self.suspension_state,
            "transaction_reference": self.transaction_reference,
            "block_reference": self.block_reference,
            "proof_metadata": self.proof_metadata,
            "details": self.details,
        }


class BlockchainEvidenceProvider(ABC):
    """Interface for verifying credential evidence on the SecureX blockchain."""

    @abstractmethod
    def verify_credential(
        self,
        credential_id: str,
        credential_fingerprint: str | None = None,
    ) -> BlockchainEvidence:
        """Return structured evidence for a credential, never faking success."""
