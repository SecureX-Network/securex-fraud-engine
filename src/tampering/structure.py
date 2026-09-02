"""Document structure analysis for tampering detection.

Inspects PDF object structure signals that are technically feasible without a
heavy external library. Does not claim visual forgery detection.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class StructureSignal:
    """A structural observation relevant to tampering."""

    signal_type: str
    description: str
    severity: str = "low"
    deterministic: bool = True
    data: dict[str, Any] = field(default_factory=dict)


def analyze_structure(data: bytes, mime_type: str) -> list[StructureSignal]:
    """Run deterministic structural checks over document bytes."""
    if mime_type != "application/pdf":
        return [
            StructureSignal(
                signal_type="structure_not_analyzed",
                description="Structural analysis only supports PDF at this time",
                severity="low",
            )
        ]
    return _analyze_pdf_structure(data)


def _analyze_pdf_structure(data: bytes) -> list[StructureSignal]:
    signals: list[StructureSignal] = []
    try:
        content = data.decode("latin-1")
    except Exception:
        return [
            StructureSignal(
                signal_type="malformed_pdf",
                description="PDF bytes could not be decoded",
                severity="high",
            )
        ]

    if not data.startswith(b"%PDF-"):
        signals.append(
            StructureSignal(
                signal_type="invalid_pdf_header",
                description="PDF does not start with a valid %PDF- header",
                severity="high",
            )
        )

    # Incremental updates can be legitimate but are worth flagging as structural context.
    if "/Prev" in content:
        signals.append(
            StructureSignal(
                signal_type="incremental_update",
                description="PDF contains incremental update markers (/Prev)",
                severity="low",
            )
        )

    if "EmbeddedFile" in content or "/EmbeddedFiles" in content:
        signals.append(
            StructureSignal(
                signal_type="embedded_files",
                description="PDF declares embedded files",
                severity="low",
            )
        )

    if content.count("/Type /Page ") == 0 and "/Type /Pages" not in content:
        signals.append(
            StructureSignal(
                signal_type="no_page_objects",
                description="PDF does not declare any page objects",
                severity="medium",
            )
        )

    if content.count("trailer") == 0:
        signals.append(
            StructureSignal(
                signal_type="missing_trailer",
                description="PDF is missing a trailer dictionary",
                severity="medium",
            )
        )

    return signals
