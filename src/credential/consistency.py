"""Credential consistency analysis.

Compares extracted document information against supplied credential metadata
and returns explicit mismatch signals. Privacy-conscious: only requires
credential references and identifiers, never unnecessary PII.
"""

from dataclasses import dataclass, field
from typing import Any

FIELD_MISMATCH = "FIELD_MISMATCH"
ISSUER_MISMATCH = "ISSUER_MISMATCH"
DATE_MISMATCH = "DATE_MISMATCH"
IDENTIFIER_MISMATCH = "IDENTIFIER_MISMATCH"
MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"


@dataclass
class ConsistencySignal:
    """A credential consistency mismatch."""

    signal_type: str
    field: str | None
    description: str
    severity: str = "medium"
    deterministic: bool = True
    data: dict[str, Any] = field(default_factory=dict)


def compare_credentials(
    extracted: dict[str, Any],
    supplied: dict[str, Any],
    required_fields: list[str] | None = None,
) -> list[ConsistencySignal]:
    """Compare extracted document fields against supplied credential metadata.

    ``extracted`` and ``supplied`` both map field names (credential_id,
    issuer_id, credential_type, issue_date, expiry_date, ...) to values.
    Values are compared case-insensitively for identifiers to avoid false
    positives from casing.
    """
    signals: list[ConsistencySignal] = []
    required = required_fields or ["credential_id", "issuer_id", "credential_type"]

    for field_name in required:
        if field_name not in supplied or supplied.get(field_name) is None:
            signals.append(
                ConsistencySignal(
                    signal_type=MISSING_REQUIRED_FIELD,
                    field=field_name,
                    description=f"Required credential field missing: {field_name}",
                    severity="high",
                )
            )

    common = set(extracted.keys()) & set(supplied.keys())
    for field_name in common:
        ev = extracted.get(field_name)
        sv = supplied.get(field_name)
        if ev is None or sv is None:
            continue
        if not _normalized_equal(ev, sv):
            signal_type = _field_mismatch_type(field_name)
            signals.append(
                ConsistencySignal(
                    signal_type=signal_type,
                    field=field_name,
                    description=f"{field_name} mismatch between document and supplied metadata",
                    severity="high" if signal_type in (ISSUER_MISMATCH, IDENTIFIER_MISMATCH) else "medium",
                )
            )

    return signals


def _field_mismatch_type(field_name: str) -> str:
    if "issuer" in field_name:
        return ISSUER_MISMATCH
    if "date" in field_name:
        return DATE_MISMATCH
    if "id" in field_name or "reference" in field_name or "number" in field_name:
        return IDENTIFIER_MISMATCH
    return FIELD_MISMATCH


def _normalized_equal(a: Any, b: Any) -> bool:
    """Compare values, normalizing case and whitespace for strings."""
    if isinstance(a, str) and isinstance(b, str):
        return a.strip().lower() == b.strip().lower()
    return a == b
