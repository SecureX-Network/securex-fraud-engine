"""Shared test fixtures and environment setup.

Ensures a test SECRET_KEY exists before any module imports
the application settings, so the suite runs without manual env.
"""

import os

if "SECRET_KEY" not in os.environ:
    os.environ["SECRET_KEY"] = "test-only-secret-key-not-for-production"

# Keep the test environment free of CI-provided real values.
for _key in ("DATABASE_URL", "SECUREX_PLATFORM_URL", "SECUREX_BLOCKCHAIN_URL"):
    os.environ.pop(_key, None)
