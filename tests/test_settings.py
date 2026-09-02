"""Configuration tests"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))



def test_settings_import():
    """Test that settings module can be imported."""
    from src.config.settings import get_settings

    settings = get_settings()
    assert settings is not None
    assert settings.API_PORT > 0
    assert isinstance(settings.LOG_LEVEL, str)


def test_environment_defaults():
    """Test that default configuration values are sensible."""
    import os
    os.environ.pop("API_PORT", None)
    os.environ.pop("API_HOST", None)

    from src.config.settings import get_settings
    settings = get_settings()

    assert settings.API_HOST == "0.0.0.0"
    assert settings.API_PORT == 8000
    assert settings.DEBUG is False
