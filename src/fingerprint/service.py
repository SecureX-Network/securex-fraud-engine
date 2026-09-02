"""Fingerprinting Service (V1 + V2).

V1 behavior is preserved: ``create``/``verify`` operate on credential data
dictionaries with SHA-256/384/512 and constant-time comparison.

V2 adds structured byte/normalized fingerprint helpers and a clear
distinction between document, credential, and analysis fingerprints.
Fingerprints never embed PII directly; they are deterministic hashes of the
provided input.
"""

import hashlib
import hmac
import json
from typing import Any

from src.core.exceptions import FingerprintError

FingerprintKind = str

DOCUMENT_FINGERPRINT: FingerprintKind = "document"
CREDENTIAL_FINGERPRINT: FingerprintKind = "credential"
ANALYSIS_FINGERPRINT: FingerprintKind = "analysis"

SUPPORTED_ALGORITHMS: dict[str, Any] = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


def _validate_algorithm(algorithm: str) -> None:
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise FingerprintError(
            message=f"Unsupported algorithm: {algorithm}",
            details={"supported": list(SUPPORTED_ALGORITHMS.keys())},
        )


def serialize_deterministically(data: Any) -> str:
    """Serialize data deterministically for consistent fingerprinting."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


class FingerprintService:
    """Service for creating and verifying fingerprints.

    Uses established cryptographic primitives (SHA-2 family) via
    Python's hashlib module.
    """

    SUPPORTED_ALGORITHMS = SUPPORTED_ALGORITHMS

    def create(self, credential_data: dict[str, Any], algorithm: str = "sha256") -> str:
        """Create a deterministic fingerprint from credential data (V1 API)."""
        return self.fingerprint_data(credential_data, algorithm)

    def verify(
        self, credential_data: dict[str, Any], expected: str, algorithm: str = "sha256"
    ) -> bool:
        """Verify credential data against an expected fingerprint (V1 API)."""
        computed = self.create(credential_data, algorithm)
        return self._constant_time_compare(computed, expected)

    # --- V2 helpers -------------------------------------------------------

    def fingerprint_bytes(self, data: bytes, algorithm: str = "sha256") -> str:
        """Fingerprint raw bytes deterministically."""
        _validate_algorithm(algorithm)
        return SUPPORTED_ALGORITHMS[algorithm](data).hexdigest()

    def fingerprint_data(self, data: Any, algorithm: str = "sha256") -> str:
        """Fingerprint arbitrary structured data deterministically."""
        _validate_algorithm(algorithm)
        serialized = serialize_deterministically(data)
        return SUPPORTED_ALGORITHMS[algorithm](serialized.encode("utf-8")).hexdigest()

    def fingerprint_normalized(
        self, data: bytes, algorithm: str = "sha256", content_type: str | None = None
    ) -> str:
        """Fingerprint normalized analysis inputs (bytes + optional content type)."""
        _validate_algorithm(algorithm)
        serialized = serialize_deterministically({"ct": content_type, "data": data.hex()})
        return SUPPORTED_ALGORITHMS[algorithm](serialized.encode("utf-8")).hexdigest()

    def verify_bytes(
        self, data: bytes, expected: str, algorithm: str = "sha256"
    ) -> bool:
        """Verify raw bytes against an expected fingerprint."""
        computed = self.fingerprint_bytes(data, algorithm)
        return self._constant_time_compare(computed, expected)

    def verify_normalized(
        self,
        data: bytes,
        expected: str,
        algorithm: str = "sha256",
        content_type: str | None = None,
    ) -> bool:
        """Verify normalized input against an expected fingerprint."""
        computed = self.fingerprint_normalized(data, algorithm, content_type)
        return self._constant_time_compare(computed, expected)

    def _serialize_deterministically(self, data: dict[str, Any]) -> str:
        return serialize_deterministically(data)

    def _constant_time_compare(self, a: str, b: str) -> bool:
        """Compare strings in a way that avoids timing attacks."""
        return hmac.compare_digest(a, b)
