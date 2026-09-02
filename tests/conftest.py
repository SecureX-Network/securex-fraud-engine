"""Shared test fixtures and environment setup.

Ensures a test SECRET_KEY exists before any module imports the application
settings, so the suite runs without manual env. Also provides a stable test
API key so V2 authenticated endpoints can be exercised.
"""

import os

if "SECRET_KEY" not in os.environ:
    os.environ["SECRET_KEY"] = "test-only-secret-key-not-for-production"

os.environ.setdefault("API_KEYS", "test-api-key")
os.environ.setdefault("ENABLE_AUTH", "true")
os.environ.setdefault("BLOCKCHAIN_VERIFY_MODE", "mock")

# Keep the test environment free of CI-provided real values.
for _key in ("DATABASE_URL", "SECUREX_PLATFORM_URL", "SECUREX_BLOCKCHAIN_URL"):
    os.environ.pop(_key, None)

TEST_API_KEY = "test-api-key"


def reset_env(*keys: str):
    """Pop the given env keys after a test that mutated them."""
    for k in keys:
        os.environ.pop(k, None)


def make_pdf(page_count: int = 1, text: str = "") -> bytes:
    """Return a minimal but valid PDF byte string for tests."""
    pages = []
    for i in range(page_count):
        page = f"{i + 3} 0 obj\n<< /Type /Page /Parent 5 0 R >>\nendobj\n"
        pages.append(page)
    text_op = ""
    if text:
        text_op = f"( {text} ) Tj"
    stream = f"<< >>\nstream\nBT /F1 12 Tf {text_op}\nET\nendstream\n"
    body = "".join(pages) + f"2 0 obj\n<< /Length {len(stream)} >>\nstream\n{stream}\nendstream\nendobj\n"
    info = "<< /Producer (TestProducer) /Creator (TestCreator) >>\n"
    root = "<< /Type /Catalog /Pages 5 0 R >>\n"
    pages_dict = f"<< /Type /Pages /Count {page_count} /Kids [ " + " ".join(f"{i + 3} 0 R" for i in range(page_count)) + " ] >>\n"
    pdf = (
        b"%PDF-1.4\n"
        + body.encode("latin-1")
        + f"5 0 obj\n{pages_dict}\nendobj\n".encode("latin-1")
        + f"6 0 obj\n{info}\nendobj\n".encode("latin-1")
        + b"7 0 obj\n" + root.encode("latin-1") + b"\nendobj\n"
        + b"trailer\n<< /Root 7 0 R /Info 6 0 R /Size 8 >>\n%%EOF\n"
    )
    return pdf


def make_png() -> bytes:
    """Return a minimal valid PNG byte signature (enough for validation)."""
    # Minimal 1x1 PNG.
    png = (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
        b"\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x00\x03\x00\x01"
        b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    return png


def make_jpeg() -> bytes:
    """Return minimal valid JPEG magic bytes (enough for validation)."""
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"
