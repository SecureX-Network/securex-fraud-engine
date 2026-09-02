"""SecureX Fraud Engine Configuration"""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # API Configuration
    API_HOST: str = Field(default="0.0.0.0", description="API host")
    API_PORT: int = Field(default=8000, description="API port")
    API_WORKERS: int = Field(default=1, description="Number of workers")
    DEBUG: bool = Field(default=False, description="Debug mode")

    # Security
    SECRET_KEY: str = Field(..., description="Secret key for signing")
    API_KEY_HEADER: str = Field(default="X-API-Key", description="API key header name")

    # Database
    DATABASE_URL: str | None = Field(default=None, description="PostgreSQL connection URL")

    # Logging
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    LOG_FORMAT: str = Field(default="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # SecureX Integration
    SECUREX_PLATFORM_URL: str | None = Field(default=None, description="SecureX Platform URL")
    SECUREX_BLOCKCHAIN_URL: str | None = Field(default=None, description="SecureX Blockchain URL")

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, description="Rate limit per minute")

    # File Upload
    MAX_UPLOAD_SIZE_MB: int = Field(default=10, description="Maximum upload size in MB")
    ALLOWED_EXTENSIONS: list[str] = Field(default=["pdf", "png", "jpg", "jpeg"], description="Allowed file extensions")

    # Fraud Detection Thresholds
    FRAUD_SCORE_THRESHOLD: float = Field(default=0.7, description="Fraud detection threshold")
    RISK_HIGH_THRESHOLD: float = Field(default=0.8, description="High risk threshold")
    RISK_MEDIUM_THRESHOLD: float = Field(default=0.5, description="Medium risk threshold")


def get_settings() -> Settings:
    """Get application settings."""
    return Settings()


# Path configuration
BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
TESTS_DIR = BASE_DIR / "tests"
DOCS_DIR = BASE_DIR / "docs"
