"""Shared authentication dependencies and key loading."""

from src.config.settings import get_settings

_KEYS_CACHE: tuple[str, ...] | None = None


def get_api_keys() -> tuple[str, ...]:
    """Load accepted API keys from configuration.

    Cached per process so the value stays stable across requests while avoiding
    repeated parsing. Keys are never logged.
    """
    global _KEYS_CACHE
    if _KEYS_CACHE is None:
        raw = get_settings().API_KEYS
        _KEYS_CACHE = tuple(k.strip() for k in raw.split(",") if k.strip())
    return _KEYS_CACHE
