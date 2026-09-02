"""Document metadata extraction.

Extracts a minimal, safe set of metadata from document bytes. No execution of
uploaded content. For PDFs the top-level Info dictionary is inspected; images
without a library yield no parsed metadata (reported as such).
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DocumentMetadata:
    """Extracted document metadata (safe subset)."""

    mime_type: str
    extracted: bool
    producer: str | None = None
    creator: str | None = None
    author: str | None = None
    title: str | None = None
    subject: str | None = None
    page_count: int | None = None
    has_embedded_files: bool = False
    incremental_update: bool = False
    raw_fields: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        d = self.raw_fields.copy()
        d["mime_type"] = self.mime_type
        d["extracted"] = self.extracted
        for k in ("producer", "creator", "author", "title", "subject"):
            if getattr(self, k) is not None:
                d[k] = getattr(self, k)
        if self.page_count is not None:
            d["page_count"] = self.page_count
        d["has_embedded_files"] = self.has_embedded_files
        d["incremental_update"] = self.incremental_update
        return d


def extract_metadata(data: bytes, mime_type: str) -> DocumentMetadata:
    """Extract safe metadata from document bytes."""
    if mime_type == "application/pdf":
        return _extract_pdf_metadata(data)
    # Image metadata parsing (EXIF etc.) requires a library; report not extracted.
    return DocumentMetadata(mime_type=mime_type, extracted=False)


def _extract_pdf_metadata(data: bytes) -> DocumentMetadata:
    try:
        content = data.decode("latin-1")
    except Exception:
        return DocumentMetadata(mime_type="application/pdf", extracted=False)

    info = _extract_info_dict(content)
    fields = {
        "producer": info.get("Producer"),
        "creator": info.get("Creator"),
        "author": info.get("Author"),
        "title": info.get("Title"),
        "subject": info.get("Subject"),
    }
    page_count = _extract_page_count(content)
    has_embedded = ("EmbeddedFile" in content) or "/EmbeddedFiles" in content
    incremental = "/Prev" in content

    return DocumentMetadata(
        mime_type="application/pdf",
        extracted=True,
        producer=fields["producer"],
        creator=fields["creator"],
        author=fields["author"],
        title=fields["title"],
        subject=fields["subject"],
        page_count=page_count,
        has_embedded_files=has_embedded,
        incremental_update=incremental,
        raw_fields={
            k: v for k, v in fields.items() if v is not None
        },
    )


def _extract_info_dict(content: str) -> dict[str, Any]:
    """Parse the top-level PDF Info dictionary key/value pairs (safe subset)."""
    result: dict[str, Any] = {}
    marker = content.find("/Info")
    if marker == -1:
        return result
    segment = content[marker : marker + 2000]

    for key in ("Producer", "Creator", "Author", "Title", "Subject"):
        start = segment.find("/" + key)
        if start == -1:
            continue
        after = segment[start + len(key) + 1 :]
        after = after.lstrip()
        if after.startswith("("):
            end = after.find(")")
            if end != -1:
                result[key] = after[1:end]
        elif after.startswith("<"):
            end = after.find(">")
            if end != -1:
                result[key] = after[1:end]
    return result


def _extract_page_count(content: str) -> int | None:
    """Heuristically count page objects in a PDF (>=1)."""
    # Count occurrences of the /Type /Page dictionary marker (not /Pages).
    count = 0
    idx = 0
    while True:
        idx = content.find("/Type", idx)
        if idx == -1:
            break
        # Look ahead to next token
        rest = content[idx:].lstrip()
        if rest.startswith("/Type"):
            rest = rest[5:].lstrip()
        else:
            idx += 1
            continue
        if rest.startswith("/Page"):
            count += 1
            idx += 5
            continue
        idx += 1
    return count if count > 0 else None
