"""SecureX Fraud Engine Custom Exceptions"""

from typing import Any


class SecureXError(Exception):
    """Base exception for SecureX Fraud Engine."""

    def __init__(
        self,
        message: str = "An error occurred",
        code: str = "SECUREX_ERROR",
        details: dict[str, Any] | None = None,
    ):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary."""
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "details": self.details,
            }
        }


class ValidationError(SecureXError):
    """Validation error."""

    def __init__(
        self,
        message: str = "Validation failed",
        field: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        details = details or {}
        if field:
            details["field"] = field
        super().__init__(message=message, code="VALIDATION_ERROR", details=details)


class FraudDetectionError(SecureXError):
    """Fraud detection error."""

    def __init__(
        self,
        message: str = "Fraud detection failed",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message=message, code="FRAUD_DETECTION_ERROR", details=details)


class RiskAnalysisError(SecureXError):
    """Risk analysis error."""

    def __init__(
        self,
        message: str = "Risk analysis failed",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message=message, code="RISK_ANALYSIS_ERROR", details=details)


class FingerprintError(SecureXError):
    """Fingerprint error."""

    def __init__(
        self,
        message: str = "Fingerprint operation failed",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message=message, code="FINGERPRINT_ERROR", details=details)


class TamperingDetectionError(SecureXError):
    """Tampering detection error."""

    def __init__(
        self,
        message: str = "Tampering detection failed",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message=message, code="TAMPERING_DETECTION_ERROR", details=details)
