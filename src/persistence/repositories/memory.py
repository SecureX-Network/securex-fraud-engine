"""In-memory repository implementations for development and tests.

These satisfy the repository interfaces without a database. They are suitable
for development/test only and are clearly not a PostgreSQL implementation.
"""

from src.persistence.models.records import (
    AnalysisRecord,
    AnalysisSubResult,
    FingerprintRecord,
)
from src.persistence.repositories.interfaces import (
    AnalysisRepository,
    AuditEventRepository,
    FingerprintRepository,
    FraudResultRepository,
    RiskResultRepository,
    TamperingResultRepository,
)


class InMemoryAnalysisRepository(AnalysisRepository):
    def __init__(self):
        self._store: dict[str, AnalysisRecord] = {}

    def save_analysis(self, record: AnalysisRecord) -> AnalysisRecord:
        self._store[record.analysis_id] = record
        return record

    def get_analysis(self, analysis_id: str) -> AnalysisRecord | None:
        return self._store.get(analysis_id)

    def list_analyses(self, limit: int = 50) -> list[AnalysisRecord]:
        return sorted(self._store.values(), key=lambda r: r.timestamp, reverse=True)[:limit]


class InMemorySubResultStore:
    """Shared storage for sub-results keyed by analysis_id."""

    def __init__(self):
        self._store: dict[str, AnalysisSubResult] = {}

    def _save(self, record: AnalysisSubResult) -> AnalysisSubResult:
        self._store[record.analysis_id] = record
        return record

    def _get(self, analysis_id: str) -> AnalysisSubResult | None:
        return self._store.get(analysis_id)


class InMemoryTamperingResultRepository(TamperingResultRepository, InMemorySubResultStore):
    def save(self, record: AnalysisSubResult) -> AnalysisSubResult:
        return self._save(record)

    def get(self, analysis_id: str) -> AnalysisSubResult | None:
        return self._get(analysis_id)


class InMemoryRiskResultRepository(RiskResultRepository, InMemorySubResultStore):
    def save(self, record: AnalysisSubResult) -> AnalysisSubResult:
        return self._save(record)

    def get(self, analysis_id: str) -> AnalysisSubResult | None:
        return self._get(analysis_id)


class InMemoryFraudResultRepository(FraudResultRepository, InMemorySubResultStore):
    def save(self, record: AnalysisSubResult) -> AnalysisSubResult:
        return self._save(record)

    def get(self, analysis_id: str) -> AnalysisSubResult | None:
        return self._get(analysis_id)


class InMemoryFingerprintRepository(FingerprintRepository):
    def __init__(self):
        self._store: dict[str, FingerprintRecord] = {}

    def save(self, record: FingerprintRecord) -> FingerprintRecord:
        self._store[record.reference_id] = record
        return record

    def get(self, reference_id: str) -> FingerprintRecord | None:
        return self._store.get(reference_id)


class InMemoryAuditEventRepository(AuditEventRepository):
    def __init__(self):
        self._events: list[dict] = []

    def record(self, event_type: str, actor: str | None, resource_type: str | None,
               resource_id: str | None, outcome: str, details: dict) -> None:
        self._events.append({
            "event_type": event_type,
            "actor": actor,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "outcome": outcome,
            "details": details,
        })
