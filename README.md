# SecureX Fraud Engine

Blockchain-Powered Digital Credential Trust Network — backend fraud, risk, document tampering, credential fingerprinting, and AI/security analysis engine.

## Purpose

This repository contains the backend analysis engine for SecureX. It provides fraud detection, risk scoring, document tampering detection, and credential fingerprinting as modular services exposed through a clean HTTP API.

It is NOT a frontend repository. The frontend lives in [securex-platform](https://github.com/SecureX-Network/securex-platform). The blockchain lives in [securex-blockchain](https://github.com/SecureX-Network/securex-blockchain).

## Architecture

```
securex-platform
        │
        │ API request
        ▼
securex-fraud-engine (this repo)
        │
        ├── Fraud Analysis
        ├── Risk Analysis
        ├── Tampering Detection
        └── Fingerprinting
        │
        ▼
Structured Security Result
        │
        ▼
securex-platform
        │
        ▼
Frontend
```

The fraud engine communicates with the platform through well-defined APIs/contracts and does not couple itself to the frontend.

## Project Structure

```
src/
├── api/          # FastAPI route definitions
├── core/         # Shared exceptions and utilities
├── fraud/        # Fraud detection service and rules
├── risk/         # Risk analysis service
├── tampering/    # Document tampering detection
├── fingerprint/  # Credential fingerprinting
├── models/       # Data models (planned)
├── services/     # Shared services (planned)
├── security/     # Security utilities (planned)
├── config/       # Environment configuration
└── main.py       # Application entry point

tests/            # Pytest test suite
docs/             # Architecture and design docs
scripts/          # Utility scripts (planned)
```

## Technology Stack

- **Python** 3.10+
- **FastAPI** for the HTTP API
- **Pydantic / pydantic-settings** for validation and configuration
- **pytest** for testing
- SHA-2 family via Python's `hashlib` for fingerprinting

## Local Setup

### Prerequisites

- Python 3.10 or higher

### Setup (macOS / Linux)

```bash
cd $HOME/ctn-fraud-engine

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Setup (Windows)

```powershell
cd $HOME\ctn-fraud-engine

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
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
| `API_HOST` | Host to bind the API |
| `API_PORT` | Port to serve the API |
| `SECRET_KEY` | Secret used for signing |
| `LOG_LEVEL` | Logging verbosity |
| `DATABASE_URL` | Optional PostgreSQL connection |
| `SECUREX_PLATFORM_URL` | Optional platform integration |
| `SECUREX_BLOCKCHAIN_URL` | Optional blockchain integration |

Never commit `.env` files containing real credentials.

## Running the Service

```bash
# Development mode (with auto-reload)
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn src.main:app --host 0.0.0.0 --port 8000
```

## Running Tests

```bash
# Full test suite
pytest

# With coverage report
pytest --cov=src --cov-report=term-missing
```

## API Overview

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |
| POST | `/api/v1/fraud/analyze` | Analyze credential for fraud indicators |
| POST | `/api/v1/risk/score` | Calculate risk score for an entity |
| POST | `/api/v1/tampering/analyze` | Analyze document for tampering |
| POST | `/api/v1/fingerprint/create` | Create a credential fingerprint |
| POST | `/api/v1/fingerprint/verify` | Verify credential against a fingerprint |

Every response includes a `request_id` for correlation. Every request is validated with structured schemas.

## Development Workflow

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Implement changes following existing patterns
3. Write tests for new behavior
4. Run `pytest` to verify
5. Run `ruff check src tests` to lint
6. Commit with a clear message
7. Open a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Security Notes

- No secrets are committed to this repository
- All configuration comes from environment variables
- Fingerprinting uses established cryptographic primitives (SHA-256/384/512)
- Constant-time string comparison prevents timing attacks
- Input validation is performed on all API requests
- No arbitrary code execution or unsafe shell commands

## Repositories

- **Fraud Engine** (this repo): [SecureX-Network/securex-fraud-engine](https://github.com/SecureX-Network/securex-fraud-engine)
- **Platform**: [SecureX-Network/securex-platform](https://github.com/SecureX-Network/securex-platform)
- **Blockchain**: [SecureX-Network/securex-blockchain](https://github.com/SecureX-Network/securex-blockchain)

## License

Proprietary. All rights reserved.
