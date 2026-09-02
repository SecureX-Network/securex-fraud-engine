# SecureX Fraud Engine Architecture (V2)

This document describes the architecture of the SecureX fraud detection, risk
analysis, document tampering detection, credential fingerprinting, document
integrity, and blockchain evidence analysis engine (V2).

## Status Legend

- **IMPLEMENTED** — code exists and is tested.
- **PARTIALLY IMPLEMENTED** — code exists with documented limitations.
- **PLANNED** — designed/ready but not implemented. Never claim it is complete.

## Overview

V2 upgrades the V1 rules engine into a production-oriented, modular backend
for fraud, risk, document integrity, tampering detection, fingerprinting, and
blockchain evidence analysis. V2 preserves all V1 APIs and adds an
authenticated `/api/v2/*` boundary plus a unified, durable analysis concept.

```
                  SecureX Platform
                         │
                  Authenticated API
                         │
                         ▼
              ┌─────────────────────┐
              │ SecureX Fraud Engine│
              │        V2           │
              └──────────┬──────────┘
                         │
       ┌─────────────────┼─────────────────┐
       ▼                 ▼                 ▼
   Fraud Engine      Risk Engine      Document Engine
       │                 │                 │
       │                 │          ┌──────┴──────┐
       │                 │          ▼             ▼
       │                 │        OCR        Tampering
       │                 │
       └─────────────────┼─────────────────┘
                         ▼
                  Evidence Aggregator
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
      SecureX Blockchain        PostgreSQL (planned)
       Evidence / Proof         Analysis Data (in-memory dev)
              │                     │
              └──────────┬──────────┘
                         ▼
                Explainable Result
```

## System Context

The `securex-platform` frontend sends authenticated credential analysis
requests to the fraud engine. V2 adds a strict service-to-service API-key
boundary so only trusted platform requests are accepted.

## V1 vs V2

| Concern | V1 | V2 |
|---------|----|----|
| API version | `/api/v1/*` | `/api/v1/*` (preserved) + `/api/v2/*` |
| Authentication | none | API key (`/api/v2/*` only) |
| Fraud | deterministic rules | extended rules + multi-signal aggregation |
| Risk | factors + score | + severity, evidence, recommendation |
| Tampering | hash + basic metadata | + structure, timestamp/author consistency |
| Fingerprinting | data dict SHA-2 | + raw bytes, normalized, typed (doc/credential/analysis) |
| Documents | none | full validation → metadata → extraction → analysis pipeline |
| Blockchain | none | adapter + states + mock provider |
| Persistence | none | interfaces + in-memory dev + PostgreSQL PLANNED |
| OCR | none | abstraction + graceful fallback (real OCR PLANNED) |
| Analysis ID | none | unified durable analysis with `analysis_id` |

## V1 vs V2 API compatibility

V1 endpoints remain functional and unchanged:

- `GET /health`, `GET /ready`
- `POST /api/v1/fraud/analyze`
- `POST /api/v1/risk/score`
- `POST /api/v1/tampering/analyze`
- `POST /api/v1/fingerprint/create`, `POST /api/v1/fingerprint/verify`

V2 adds:

- `POST /api/v2/fraud/analyze`
- `POST /api/v2/risk/score`
- `POST /api/v2/documents/analyze`
- `POST /api/v2/tampering/analyze`
- `POST /api/v2/fingerprint/create`, `POST /api/v2/fingerprint/verify`
- `POST /api/v2/blockchain/verify`
- `POST /api/v2/analysis`
- `GET /api/v2/analysis/{id}`
- `GET /api/v2/analysis/{id}/evidence`

## Component Descriptions

### Authentication (`src/security/authentication`)

IMPLEMENTED. API-key service-to-service auth for the V2 boundary. Keys are
read from the `API_KEYS` environment variable (comma-separated) and matched
using constant-time comparison. Keys are never logged. `ENABLE_AUTH=false`
disables auth for local development only; it does not weaken production
(production should keep it enabled).

### File Security (`src/security/file_security`)

IMPLEMENTED. Guards against path traversal, unsafe filenames, oversized
uploads, and provides secure temporary-file cleanup. Includes a `redact`
helper that strips keys, secrets, and PII from structured logs.

### Audit (`src/security/audit`)

PARTIALLY IMPLEMENTED. An audit event model and repository interface exist.
Wiring audit events into a durable store is PLANNED (depends on persistence).

### Documents (`src/documents`)

IMPLEMENTED (validation, metadata, extraction pipeline; OCR abstraction).

Pipeline:

```
upload → validate → fingerprint → metadata → text extraction/OCR → tampering → result
```

- **Validation** (`validation/service.py`): signature (magic-byte) detection
  for PDF/PNG/JPEG, MIME/extension checks, size limits, empty/malformed
  detection, unsupported format rejection. Never executes uploaded content.
- **Metadata** (`metadata/service.py`): safe PDF metadata (producer, creator,
  author, title, page count, embedded files, incremental updates).
- **Extraction** (`extraction/`): `DocumentExtractor` + `TextExtractionService`
  abstraction. Includes a conservative dependency-free PDF text-stream
  extractor. It reports "no extractable text" rather than fabricating content.
- **OCR** (`ocr/`): `OCRProvider` interface + `NoOCRProvider` default.
  Real OCR (Tesseract etc.) is PLANNED; OCR is never mandatory and never fakes
  extracted text.
- **Pipeline** (`pipeline.py`): `DocumentAnalysisService` orchestrates the
  secure flow.

### Tampering (`src/tampering`)

IMPLEMENTED. Deterministic hash-integrity comparison, suspicious metadata
(named fields), V2 timestamp/author consistency, document-type check, and PDF
structural analysis (incremental updates, embedded files, missing trailer,
page objects). Returns structured evidence, deterministic confidence, an
aggregated severity, and an explanation. Does not claim visual forgery
detection.

### Credential Consistency (`src/credential/consistency.py`)

IMPLEMENTED. Compares extracted document fields against supplied credential
metadata and returns explicit signals: `FIELD_MISMATCH`, `ISSUER_MISMATCH`,
`DATE_MISMATCH`, `IDENTIFIER_MISMATCH`, `MISSING_REQUIRED_FIELD`. These feed
fraud/risk aggregation. Privacy-conscious: only credential references and
identifiers are required.

### Fingerprinting (`src/fingerprint`)

IMPLEMENTED. SHA-256/384/512 via `hashlib`. Deterministic output, constant-time
verification (`hmac.compare_digest`). Types:
- document fingerprint (raw bytes)
- credential fingerprint (structured data)
- analysis fingerprint (normalized inputs)

Fingerprints never embed PII. Hashing alone is not proof of authenticity.

### Fraud (`src/fraud`)

IMPLEMENTED. Deterministic rules (issuer reputation, issuer mismatch,
duplicate fingerprints, verification history) combined with V2 signals:
document/tampering signals, blockchain evidence state, and consistency
mismatches. Produces fraud score, confidence, severity, and explanation.

### Risk (`src/risk`)

IMPLEMENTED. Transparent deterministic score from weighted factors. Returns
numeric score, level (low/medium/high/critical), severity, factors, evidence,
recommendation, and explanation. Reproducible for identical inputs.

### Blockchain (`src/blockchain`)

PARTIALLY IMPLEMENTED. Clean `BlockchainEvidenceProvider` interface, an
HTTP `SecureXBlockchainClient`, a `LiveBlockchainEvidenceProvider` (parses the
SecureX permissioned blockchain endpoint), and a `MockBlockchainEvidenceProvider`
for tests. States: `VERIFIED`, `NOT_FOUND`, `REVOKED`, `SUSPENDED`,
`VERIFICATION_FAILED`, `UNCONFIGURED`, `UNAVAILABLE`. Verification never fakes
success and remains testable without a live blockchain.

**Not rebuilt:** no Ethereum/Web3, no tokens/gas/mining/PoW/NFTs/DeFi.

### Persistence (`src/persistence`)

PARTIALLY IMPLEMENTED. Repository interfaces for Analysis, Fingerprint,
TamperingResult, RiskResult, FraudResult, and AuditEvent. Default
implementation is an in-memory dev/test repository set. **PostgreSQL is
PLANNED** via `DATABASE_URL`; a real Postgres implementation is NOT yet
implemented and persistence is never faked.

### Unified Analysis (`src/analysis`)

IMPLEMENTED. `AnalysisService` orchestrates document + credential consistency +
blockchain + tampering + fraud + risk into one durable `analysis_id`, persists
the result, and supports retrieval. Status values: `completed`, `partial`,
`failed`.

### ML (`src/models/interfaces.py`)

PLANNED. `FraudModel`, `RiskModel`, `TamperingModel` protocol interfaces are
defined for future plug-in of real trained models. **No production ML model is
implemented**; no accuracy claims are made and no fake confidence is generated.
Engine remains fully deterministic.

## Privacy Model

SecureX follows data minimization. Preferred data: `credential_id`,
`issuer_id`, `fingerprint`, `analysis_id`, cryptographic evidence, status, and
risk signals — not full names, addresses, emails, or full certificate contents.
PII is never placed inside fingerprints. Uploaded document bytes are processed
in memory / temporary files and are not permanently stored. Persistence
records capture analysis data only.

## Security

- API-key authentication for the V2 boundary (constant-time comparison).
- Path-traversal and unsafe-filename rejection.
- Upload size limits via magic-byte validation.
- No execution of uploaded content; no arbitrary shell commands.
- No arbitrary user-supplied URL fetching (blockchain client only uses
  configured `SECUREX_BLOCKCHAIN_URL`; no SSRF from user input).
- Secret redaction in logs; secrets never committed.
- Structured, deterministic scoring (no fabricated confidence).
- Secure temporary-file cleanup.

## Configuration

See `.env.example`. Key variables: `API_KEYS`, `ENABLE_AUTH`,
`SECUREX_BLOCKCHAIN_URL`, `BLOCKCHAIN_VERIFY_MODE`, `MAX_UPLOAD_SIZE_MB`,
`DATABASE_URL`, `REQUIRED_CREDENTIAL_FIELDS`.

## Testing

- `pytest` — full suite (V1 + V2).
- `pytest --cov=src --cov-report=term-missing` — coverage.
- `ruff check src tests` — lint.
- Coverage target: ≥ 80% (current exceeds this).

## Limitations (honest)

- PDF structural analysis and text extraction are intentionally conservative;
  complex PDFs / scanned images may report "no extractable text".
- Real OCR is PLANNED; the engine currently reports OCR as unavailable unless a
  provider is wired in.
- Blockchain integration requires a live SecureX blockchain endpoint; without
  one the engine reports structured `NOT_CONFIGURED`/`UNAVAILABLE` states.
- PostgreSQL persistence is PLANNED; the dev/test in-memory repository is the
  only current implementation.
- No production ML model is implemented.

## Future ML Architecture

The interfaces in `src/models/interfaces.py` define where real models can be
added later. Any future model must specify version, input/output definitions,
confidence semantics, evaluation notes, and test coverage, and must remain
isolated so the application does not depend on a single model.
