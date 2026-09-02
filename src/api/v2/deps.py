"""Shared V2 API helpers and dependencies."""

from fastapi import Depends

from src.security.authentication.service import verify_api_key


def require_auth(auth: None = Depends(verify_api_key)) -> None:
    """V2 dependency requiring a valid API key (unless auth disabled)."""
    return None
