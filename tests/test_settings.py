"""Configuration tests"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def test_settings_import():
    """Test that settings module can be imported."""
    from src.config.settings import get_settings

    settings = get_settings()
    assert settings is not None
    assert settings.API_PORT > 0
    assert isinstance(settings.LOG_LEVEL, str)


def test_environment_defaults(monkeypatch):
    """Test that default configuration values are sensible."""
    monkeypatch.delenv("API_PORT", raising=False)
    monkeypatch.delenv("API_HOST", raising=False)
    monkeypatch.delenv("DEBUG", raising=False)

    from src.config.settings import get_settings

    settings = get_settings()

    assert settings.API_HOST == "0.0.0.0"
    assert settings.API_PORT == 8000
    assert settings.DEBUG is False
