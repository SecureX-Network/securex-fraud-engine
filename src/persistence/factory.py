"""Persistence container providing repository instances.

PostgreSQL is PLANNED. Until a DATABASE_URL-backed implementation exists, this
returns in-memory repositories suitable for development and tests. Persistence
behavior is deterministic and never fakes a database write.
"""

from dataclasses import dataclass

from src.persistence.repositories.interfaces import (
    AnalysisRepository,
    AuditEventRepository,
    FingerprintRepository,
    FraudResultRepository,
    RiskResultRepository,
    TamperingResultRepository,
)
from src.persistence.repositories.memory import (
    InMemoryAnalysisRepository,
    InMemoryAuditEventRepository,
    InMemoryFingerprintRepository,
    InMemoryFraudResultRepository,
    InMemoryRiskResultRepository,
    InMemoryTamperingResultRepository,
)


@dataclass
class Persistence:
    """Container of repository instances."""

    analyses: AnalysisRepository
    tampering: TamperingResultRepository
    risk: RiskResultRepository
    fraud: FraudResultRepository
    fingerprints: FingerprintRepository
    audit: AuditEventRepository


def create_persistence(use_postgres: bool = False) -> Persistence:
    """Create a persistence container.

    ``use_postgres`` is accepted for forward-compatibility but currently always
    returns in-memory repositories because no PostgreSQL implementation exists.
    """
    return Persistence(
        analyses=InMemoryAnalysisRepository(),
        tampering=InMemoryTamperingResultRepository(),
        risk=InMemoryRiskResultRepository(),
        fraud=InMemoryFraudResultRepository(),
        fingerprints=InMemoryFingerprintRepository(),
        audit=InMemoryAuditEventRepository(),
    )
