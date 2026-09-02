"""Fingerprinting Service"""

import hashlib
import hmac
import json
from typing import Any

from src.core.exceptions import FingerprintError


class FingerprintService:
    """Service for creating and verifying credential fingerprints.

    Uses established cryptographic primitives (SHA-2 family) via
    Python's hashlib module.
    """

    SUPPORTED_ALGORITHMS = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}

    def create(self, credential_data: dict[str, Any], algorithm: str = "sha256") -> str:
        """Create a deterministic fingerprint from credential data."""
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise FingerprintError(
                message=f"Unsupported algorithm: {algorithm}",
                details={"supported": list(self.SUPPORTED_ALGORITHMS.keys())},
            )

        serialized = self._serialize_deterministically(credential_data)
        hash_fn = self.SUPPORTED_ALGORITHMS[algorithm]
        return hash_fn(serialized.encode("utf-8")).hexdigest()

    def verify(self, credential_data: dict[str, Any], expected: str, algorithm: str = "sha256") -> bool:
        """Verify credential data against an expected fingerprint."""
        computed = self.create(credential_data, algorithm)
        return self._constant_time_compare(computed, expected)

    def _serialize_deterministically(self, data: dict[str, Any]) -> str:
        """Serialize data deterministically for consistent fingerprinting."""
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    def _constant_time_compare(self, a: str, b: str) -> bool:
        """Compare strings in a way that avoids timing attacks."""
        return hmac.compare_digest(a, b)
