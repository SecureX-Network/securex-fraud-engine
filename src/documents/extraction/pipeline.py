"""Default document extractor implementation.

Handles graceful failure for unsupported documents, scanned documents,
OCR failure, and missing extraction libraries. Text is never fabricated.
"""

from src.documents.extraction.service import DocumentExtractor, OCRResult


class DefaultDocumentExtractor(DocumentExtractor):
    """Extracts text where possible and reports unavailability otherwise.

    PDF: a lightweight built-in text stream extractor runs when no dedicated
    library is installed. If no text is found the document is treated as
    scanned/not-extractable and reported as such.
    Images: delegated to the OCR provider when available.
    """

    def extract(self, data: bytes, mime_type: str) -> OCRResult:
        if mime_type == "application/pdf":
            return self._extract_pdf(data)
        if mime_type in ("image/png", "image/jpeg"):
            return self._extract_image(data)
        return OCRResult(
            text=None,
            method="none",
            available=False,
            note="Unsupported document type for text extraction",
        )

    def _extract_pdf(self, data: bytes) -> OCRResult:
        try:
            text = extract_pdf_ascii_text(data)
        except Exception:
            text = None
        if not text:
            return OCRResult(
                text=None,
                method="pdf_stream",
                available=True,
                note="No extractable text stream found (scanned or image-only PDF)",
            )
        return OCRResult(
            text=text,
            method="pdf_stream",
            available=True,
            note="Text extracted from PDF content streams",
        )

    def _extract_image(self, data: bytes) -> OCRResult:
        if self.ocr_provider.available():
            try:
                text = self.ocr_provider.extract_text(data)
            except Exception:
                text = None
            return OCRResult(
                text=text,
                method=self.ocr_provider.name,
                available=True,
                note="OCR applied" if text else "OCR produced no text",
            )
        return OCRResult(
            text=None,
            method="none",
            available=False,
            note="OCR provider not configured",
        )


def extract_pdf_ascii_text(data: bytes) -> str | None:
    """Return the first text stream found in a PDF, if any.

    This is a conservative, dependency-free heuristic that reads literal
    ``Tj``/``TJ`` text operators from content streams. It is intentionally
    limited: complex PDFs, compressed streams, or fonts without ToUnicode maps
    will yield no text, which is reported as "no extractable text" rather than
    fabricating content. A dedicated PDF/OCR library (PLANNED) will replace it.
    """
    try:
        content = data.decode("latin-1")
    except Exception:
        return None

    fragments: list[str] = []
    # Literal strings shown via Tj
    for block in _iter_paren_operators(content, "Tj"):
        fragments.append(block)
    # TJ arrays show each parenthesized string in the same operator
    for block in _iter_tj_arrays(content):
        fragments.append(block)

    if not fragments:
        return None
    return "\n".join(f for f in fragments if f.strip())


def _iter_paren_operators(content: str, op: str) -> list[str]:
    """Extract parenthesized string literals immediately before ``op``."""
    out: list[str] = []
    idx = 0
    while True:
        idx = content.find(op, idx)
        if idx == -1:
            break
        # Search backwards for an opening parenthesis
        start = content.rfind("(", 0, idx)
        if start != -1:
            end = _find_closing_paren(content, start)
            if end != -1 and end < idx:
                out.append(_unicode_pdf_string(content[start + 1 : end]))
        idx += len(op)
    return out


def _iter_tj_arrays(content: str) -> list[str]:
    """Extract parenthesized strings inside a ``[...] Tj`` array operator."""
    out: list[str] = []
    idx = 0
    while True:
        idx = content.find("TJ", idx)
        if idx == -1:
            break
        # Locate the opening bracket before TJ
        open_bracket = content.rfind("[", 0, idx)
        if open_bracket != -1 and content[open_bracket:idx].count("[") > 0:
            fragment = content[open_bracket + 1 : idx]
            tmp = fragment
            while "(" in tmp:
                s = tmp.find("(")
                e = _find_closing_paren(tmp, s)
                if e == -1:
                    break
                out.append(_unicode_pdf_string(tmp[s + 1 : e]))
                tmp = tmp[e + 1 :]
        idx += len("TJ")
    return out


def _find_closing_paren(content: str, start: int) -> int:
    """Find the index of the closing parenthesis matching ``start``."""
    depth = 0
    for i in range(start, len(content)):
        ch = content[i]
        if ch == "\\":
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _unicode_pdf_string(raw: str) -> str:
    """Best-effort decode of a PDF literal string (latin-1, unescaping)."""
    out: list[str] = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            mapping = {
                "n": "\n",
                "r": "\r",
                "t": "\t",
                "b": "\b",
                "f": "\f",
                "(": "(",
                ")": ")",
                "\\": "\\",
            }
            out.append(mapping.get(nxt, nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)
