"""Repository interfaces for persistence.

These define the boundary between business logic and storage. A PostgreSQL
implementation (PLANNED) can satisfy these interfaces without changing the
services that depend on them.
"""

from abc import ABC, abstractmethod

from src.persistence.models.records import (
    AnalysisRecord,
    AnalysisSubResult,
    FingerprintRecord,
)


class AnalysisRepository(ABC):
    """Storage for unified analysis records."""

    @abstractmethod
    def save_analysis(self, record: AnalysisRecord) -> AnalysisRecord: ...

    @abstractmethod
    def get_analysis(self, analysis_id: str) -> AnalysisRecord | None: ...

    @abstractmethod
    def list_analyses(self, limit: int = 50) -> list[AnalysisRecord]: ...


class TamperingResultRepository(ABC):
    """Storage for tampering results."""

    @abstractmethod
    def save(self, record: AnalysisSubResult) -> AnalysisSubResult: ...

    @abstractmethod
    def get(self, analysis_id: str) -> AnalysisSubResult | None: ...


class RiskResultRepository(ABC):
    """Storage for risk results."""

    @abstractmethod
    def save(self, record: AnalysisSubResult) -> AnalysisSubResult: ...

    @abstractmethod
    def get(self, analysis_id: str) -> AnalysisSubResult | None: ...


class FraudResultRepository(ABC):
    """Storage for fraud results."""

    @abstractmethod
    def save(self, record: AnalysisSubResult) -> AnalysisSubResult: ...

    @abstractmethod
    def get(self, analysis_id: str) -> AnalysisSubResult | None: ...


class AuditEventRepository(ABC):
    """Storage for audit events."""

    @abstractmethod
    def record(self, event_type: str, actor: str | None, resource_type: str | None,
               resource_id: str | None, outcome: str, details: dict) -> None: ...


class FingerprintRepository(ABC):
    """Storage for fingerprint references."""

    @abstractmethod
    def save(self, record: FingerprintRecord) -> FingerprintRecord: ...

    @abstractmethod
    def get(self, reference_id: str) -> FingerprintRecord | None: ...
