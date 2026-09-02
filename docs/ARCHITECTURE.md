# SecureX Fraud Engine Architecture

This document describes the architecture of the SecureX fraud detection, risk analysis, document tampering detection, and credential fingerprinting engine.

## Overview

The fraud engine is a modular backend service that processes security-sensitive credential data through a clean HTTP API. It is designed to be extensible and to integrate with the SecureX platform and blockchain without tight coupling.

## System Context

```
securex-platform
        │
        │ API request
        ▼
┌─────────────────────────────────────┐
│      Fraud Engine API (FastAPI)     │
├─────────────────────────────────────┤
│  Analysis Services                  │
│   ├── Fraud                         │
│   ├── Risk                          │
│   ├── Tampering                     │
│   └── Fingerprint                   │
├─────────────────────────────────────┤
│  Output: Structured Security Result │
└─────────────────────────────────────┘
```

The frontend (securex-platform) sends API requests and receives structured results. It never calls internal implementation details directly.

## Component Descriptions

### Platform

The `securex-platform` frontend sends credential analysis requests to the fraud engine. It presents results to end users.

### Fraud Engine API

FastAPI-based HTTP interface that receives requests, validates them with Pydantic schemas, and routes them to the appropriate analysis service.

**Endpoints:**
- `GET /health` — Service health check
- `POST /api/v1/fraud/analyze` — Credential fraud analysis
- `POST /api/v1/risk/score` — Risk score calculation
- `POST /api/v1/tampering/analyze` — Document tampering analysis
- `POST /api/v1/fingerprint/create` — Create credential fingerprint
- `POST /api/v1/fingerprint/verify` — Verify credential against fingerprint

### Analysis Services

#### Fraud

Analyzes credential-related signals to identify suspicious behavior or credentials.

**V1 Implementation:** Rules-based engine evaluating:
- Issuer reputation
- Issuer mismatch
- Duplicate/reused fingerprints
- Verification history anomalies
- Verification failure rates

**Planned:** Machine learning model augmentation via a common interface.

#### Risk

Provides a modular risk-analysis layer with the pipeline:

```
Input Signals → Feature Extraction → Risk Analysis → Risk Score → Risk Explanation → Fraud Result
```

**V1 Implementation:** Deterministic rules-based baseline considering:
- Entity age
- Historical behavior
- Signal analysis

**Planned:** Replacement/augmentation with trained ML models behind the same interface.

#### Tampering

Designs the service boundary for document integrity/tampering analysis.

**V1 Implementation:**
- Document hash comparison
- Suspicious metadata detection
- Document type validation

**Planned (not yet implemented):**
- Image/document metadata analysis
- Structural inconsistency detection
- Visual anomaly detection
- Region-level analysis
- OCR-assisted consistency checks
- Original-vs-submitted comparison

#### Fingerprint

Provides secure, deterministic fingerprinting using SHA-2 (256/384/512) via Python's `hashlib`.

**Capabilities:**
- Credential integrity comparison
- Duplicate detection
- Tampering detection support
- Verification workflows

Fingerprints do not contain PII. Only a deterministic hash of the provided data. Constant-time comparison (`hmac.compare_digest`) prevents timing attacks.

## Future Integration Points

The following are planned integration points that do not exist yet. They are documented to guide future work without being claimed as implemented.

### Blockchain Integration

- **Status:** Planned
- The blockchain lives in `securex-blockchain` and is NOT reimplemented here.
- May consume: credential transaction history, lifecycle events, issuer information, integrity proofs, verification history.
- Integration would use an API/service boundary.

### ML Model Integration

- **Status:** Planned
- The risk and fraud services define interfaces where trained models can be added.
- Any model must have: version, input definition, output definition, confidence semantics, evaluation notes, test coverage.
- Model-specific code must be isolated; the application must not depend on any single model.

### PostgreSQL Persistence

- **Status:** Optional/planned
- Configuration hooks exist via `DATABASE_URL`.
- Not required for V1 analysis endpoints that operate on request data only.

## Privacy Model

SecureX avoids unnecessarily copying sensitive credential data into the fraud engine. The preferred pattern is:

```
Credential reference
+ Required analysis input
+ Cryptographic proof/fingerprint
```

Rather than storing complete credential records. The service processes only what is sent in the request.

## Security

- All configuration from environment variables
- No hard-coded credentials or secrets
- Input validation on every endpoint
- Consistent error handling without leaking internals
- Request IDs for correlation
- Structured logging without sensitive data
- Constant-time comparison for fingerprint verification
- Safe file upload validation (size and type limits)
