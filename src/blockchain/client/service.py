"""HTTP client for the SecureX blockchain evidence endpoint.

Uses httpx. Only fetches from the configured ``SECUREX_BLOCKCHAIN_URL``; it
never accepts arbitrary user-supplied URLs (no SSRF risk).
"""

from src.core.exceptions import BlockchainError
from src.security.file_security import redact


class SecureXBlockchainClient:
    """Thin HTTP client for the blockchain evidence endpoint."""

    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def verify_credential(self, credential_id: str, credential_fingerprint: str | None = None) -> dict:
        """Request evidence for a credential. Raises on transport errors."""
        import httpx

        url = f"{self.base_url}/api/v1/credentials/{credential_id}/evidence"
        payload: dict[str, object] = {}
        if credential_fingerprint:
            payload["credential_fingerprint"] = credential_fingerprint
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPStatusError as exc:
            raise BlockchainError(
                message="Blockchain evidence endpoint returned an error",
                details={"status_code": exc.response.status_code},
            )
        except httpx.HTTPError as exc:
            raise BlockchainError(
                message="Blockchain endpoint unreachable",
                details={"error": str(exc)},
            ) from exc

    def __repr__(self) -> str:
        return f"SecureXBlockchainClient(base_url={redact(self.base_url)!r})"
