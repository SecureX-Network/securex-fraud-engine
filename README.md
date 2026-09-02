# SecureX Fraud Engine (V2)

Blockchain-Powered Digital Credential Trust Network — backend fraud, risk,
document integrity, tampering detection, credential fingerprinting, and
blockchain evidence analysis engine.

> **Status:** V2 implemented. V1 APIs fully preserved. Some capabilities are
> honestly documented as **PLANNED** (real OCR, PostgreSQL, production ML).

## Purpose

Backend analysis engine for SecureX. Provides fraud detection, risk scoring,
document tampering detection, credential fingerprinting, document-integrity
analysis, and blockchain evidence verification as modular services exposed
through a clean HTTP API.

It is **not** a frontend repository. The frontend lives in
[securex-platform](https://github.com/SecureX-Network/securex-platform). The
blockchain lives in [securex-blockchain](https://github.com/SecureX-Network/securex-blockchain).

## V1 vs V2

- **V1** is fully preserved (same endpoints, same request/response contracts).
- **V2** adds an authenticated `/api/v2/*` boundary, document analysis,
  tampering structure/content analysis, credential consistency, blockchain
  evidence integration, unified durable analyses, and richer fingerprinting.

## Architecture

```
              ┌─────────────────────┐
              │ SecureX Fraud Engine│
              │        V2           │
              └──────────┬──────────┘
       ┌─────────────────┼─────────────────┐
       ▼                 ▼                 ▼
   Fraud Engine      Risk Engine      Document Engine
       │                 │                 │
       │                 │          ┌──────┴──────┐
       │                 │          ▼             ▼
       │                 │        OCR        Tampering
       └─────────────────┼─────────────────┘
                         ▼
                  Evidence Aggregator
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
      SecureX Blockchain        PostgreSQL (planned)
                                   (in-memory dev now)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

## Project Structure

```
src/
├── api/            # FastAPI route definitions (V1 + V2 routers)
├── core/           # Shared exceptions and utilities
├── fraud/          # Fraud detection service and rules
├── risk/           # Risk analysis service
├── tampering/      # Document tampering detection (+ structure analysis)
├── fingerprint/    # Credential fingerprinting
├── documents/      # Validation, metadata, text extraction, OCR
├── credential/     # Credential consistency analysis
├── blockchain/     # Client, adapter, verification (evidence)
├── persistence/    # Repository interfaces + in-memory dev repo
├── security/       # Authentication, authorization, file security, audit
├── models/         # ML model interfaces (PLANNED)
├── services/       # Shared services
├── config/         # Environment configuration
└── main.py         # Application entry point

tests/              # Pytest test suite (V1 + V2)
docs/               # Architecture and design docs
```

## Technology Stack

- **Python** 3.10+
- **FastAPI** for the HTTP API
- **Pydantic / pydantic-settings** for validation and configuration
- **pytest** for testing
- **httpx** for the blockchain client
- **python-multipart** for secure document uploads
- SHA-2 family via `hashlib` for fingerprinting

## Local Setup

### Prerequisites

- Python 3.10 or higher

### Setup (macOS / Linux)

```bash
cd $HOME/ctn-fraud-engine

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Setup (Windows)

```powershell
cd $HOME\ctn-fraud-engine

python -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Environment Configuration

Copy `.env.example` to `.env` and set your values:

```bash
cp .env.example .env
```

Key settings:

| Variable | Purpose |
|----------|---------|
| `API_HOST` / `API_PORT` | Bind host / port |
| `SECRET_KEY` | Signing secret |
| `ENABLE_AUTH` | Toggle V2 API-key auth (default `true`) |
| `API_KEYS` | Comma-separated accepted API keys for V2 |
| `SECUREX_BLOCKCHAIN_URL` | Blockchain evidence endpoint |
| `BLOCKCHAIN_VERIFY_MODE` | `mock` \| `live` \| `unavailable` |
| `MAX_UPLOAD_SIZE_MB` | Document upload limit |
| `DATABASE_URL` | PostgreSQL (PLANNED) |
| `LOG_LEVEL` | Logging verbosity |

Never commit `.env` files containing real credentials.

## Running the Service

```bash
# Development mode (with auto-reload)
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn src.main:app --host 0.0.0.0 --port 8000
```

## API Overview

### V1 (preserved, unauthenticated)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |
| POST | `/api/v1/fraud/analyze` | Fraud analysis |
| POST | `/api/v1/risk/score` | Risk score |
| POST | `/api/v1/tampering/analyze` | Tampering analysis |
| POST | `/api/v1/fingerprint/create` | Create fingerprint |
| POST | `/api/v1/fingerprint/verify` | Verify fingerprint |

### V2 (authenticated with `X-API-Key`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v2/fraud/analyze` | Unified fraud analysis |
| POST | `/api/v2/risk/score` | Risk score with evidence |
| POST | `/api/v2/documents/analyze` | Secure document pipeline |
| POST | `/api/v2/tampering/analyze` | Tampering with structure/consistency |
| POST | `/api/v2/fingerprint/create` | Fingerprint (bytes/structured/typed) |
| POST | `/api/v2/fingerprint/verify` | Verify fingerprint (constant-time) |
| POST | `/api/v2/blockchain/verify` | Blockchain evidence verification |
| POST | `/api/v2/analysis` | Run unified analysis → `analysis_id` |
| GET | `/api/v2/analysis/{id}` | Retrieve analysis |
| GET | `/api/v2/analysis/{id}/evidence` | Retrieve evidence references |

Every response includes a `request_id` and structured validation. V2 responses
include `explanation`, deterministic `confidence`, and `severity`.

## Authentication

V2 endpoints require an API key sent via the `X-API-Key` header (configurable
via `API_KEY_HEADER`). Accepted keys come from `API_KEYS`. Constant-time
comparison prevents timing attacks. For local development without auth, set
`ENABLE_AUTH=false` — but keep it enabled in production.

```bash
curl -X POST /api/v2/fraud/analyze \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{...}'
```

## Testing

```bash
# Full test suite (V1 + V2)
pytest

# With coverage report
pytest --cov=src --cov-report=term-missing

# Lint
ruff check src tests
```

## Security Notes

- API-key authentication for the V2 boundary (constant-time comparison).
- Path-traversal and unsafe-filename rejection.
- Magic-byte format validation and upload size limits.
- Uploaded documents are processed in memory / temporary files; never executed,
  never permanently stored by default.
- No arbitrary shell commands, no user-supplied URL fetching, no SSRF from user
  input.
- Secret redaction in logs; secrets never committed.
- Deterministic scoring only — no fabricated ML confidence.
- Constant-time fingerprint comparison.

## Privacy

SecureX follows data minimization (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)).
Fingerprints never contain PII; persistence stores analysis data only.

## Current Capability Status

- **IMPLEMENTED:** V1 + V2 APIs, document validation/metadata/extraction,
  tampering (hash/metadata/structure/consistency), fingerprinting (bytes/
  structured/typed), fraud/risk aggregation, blockchain adapter + mock,
  unified analyses, API-key auth, audit model, in-memory persistence.
- **PARTIALLY IMPLEMENTED:** PDF structural/text extraction is conservative;
  blockchain requires a live endpoint for `live` mode.
- **PLANNED:** Real OCR provider, PostgreSQL persistence, production ML models.

## Repositories

- **Fraud Engine** (this repo): [SecureX-Network/securex-fraud-engine](https://github.com/SecureX-Network/securex-fraud-engine)
- **Platform**: [SecureX-Network/securex-platform](https://github.com/SecureX-Network/securex-platform)
- **Blockchain**: [SecureX-Network/securex-blockchain](https://github.com/SecureX-Network/securex-blockchain)

## License

Proprietary. All rights reserved.
