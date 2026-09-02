"""API key based service-to-service authentication for the V2 API boundary.

Keys are supplied via the ``API_KEYS`` environment variable (comma-separated).
This creates a clean boundary between the authenticated securex-platform and the
fraud engine without weakening production security. Keys are never logged.
"""

import hmac

from fastapi import Depends, HTTPException, Request, status

from src.config.settings import get_settings
from src.core.exceptions import AuthenticationError
from src.security.authentication.dependencies import get_api_keys


def verify_api_key(request: Request) -> None:
    """Reject the request unless a valid API key is supplied.

    When authentication is disabled in configuration (dev/test only) the check
    passes. A safe message is returned; the key itself is never exposed.
    """
    settings = get_settings()
    if not settings.ENABLE_AUTH:
        return

    if not settings.API_KEYS:
        raise AuthenticationError(
            message="API authentication is enabled but no keys are configured"
        )

    header_name = settings.API_KEY_HEADER
    supplied = request.headers.get(header_name)

    if not supplied:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )

    for key in get_api_keys():
        if hmac.compare_digest(supplied, key):
            return

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )


async def require_api_key(auth: None = Depends(verify_api_key)) -> None:
    """Dependency that enforces API key authentication on a route."""
    return None
