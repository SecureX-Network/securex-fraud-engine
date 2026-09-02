# Contributing to SecureX Fraud Engine

Thank you for your interest in contributing. This guide covers the development workflow, standards, and security requirements.

## Repository Scope

This repository is the backend fraud/risk/security analysis engine. It is **not** a frontend repository. Do not add frontend code here. The platform frontend lives in `securex-platform` and the blockchain in `securex-blockchain`.

## Versioning and Backwards Compatibility

- **Do not break V1.** The `/api/v1/*` endpoints and their request/response contracts must remain stable.
- New functionality goes behind `/api/v2/*`.
- Do not remove or silently change V1 contracts.
- Reuse V1 services internally rather than duplicating business logic.

## Getting Started

```bash
git clone https://github.com/SecureX-Network/securex-fraud-engine.git
cd securex-fraud-engine
git checkout -b feature/your-feature
```

## Branching

- `main` is the stable branch. It must always be deployable.
- Use descriptive feature branches: `feature/risk-ml-model`, `fix/fingerprint-timing-issue`, `docs/api-schema`.
- Branch names should be lowercase with hyphens.

## Commits

- Write clear, concise commit messages.
- Follow conventional commits format: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`.
- Reference issue numbers where applicable.
- Do not commit large binary files or generated artifacts.
- Do not force-push to shared branches.

## code style

- Follow PEP 8 and the patterns used in existing code.
- Run `ruff check src tests` before committing.
- Keep modules small, focused, and testable.
- Do not add comments unless they add real value.

## Testing

- Always add tests for new functionality.
- Run the full test suite before pushing:
  ```bash
  pytest
  ```
- Aim for at least 80% coverage of core security logic.
- Use deterministic fixtures. Do not assert against fabricated data.
- Tests must pass on both macOS and Windows where practical.
- Maintain the V1 tests and add V2 tests in `tests/` alongside them.

## V2 Engineering Principles

- **No fabricated AI/ML.** The engine is deterministic. Do not invent model
  accuracy or fake confidence scores. Use the ML interfaces in
  `src/models/interfaces.py` for PLANNED models only.
- **No fake blockchain verification.** Use the `BlockchainEvidenceProvider`
  interface and the mock provider for tests. Never claim `VERIFIED` without a
  real verification path.
- **No fake persistence.** PostgreSQL is PLANNED. Use the in-memory dev
  repositories via `src/persistence`; do not claim a database write that does
  not happen.
- **Do not rebuild the SecureX blockchain** or add cryptocurrency/Web3
  functionality.
- **Never execute uploaded documents** or run arbitrary shell commands against
  uploaded content.
- **Never accept arbitrary URLs from users to fetch.**
- New V2 API routes must apply the `require_auth` dependency.

## Security

- Never commit secrets: API keys, private keys, passwords, `.env` files, or production credentials.
- Never log sensitive data (credential content, PII, keys).
- All configuration must come from environment variables, not hard-coded values.
- Use established cryptographic primitives; never invent cryptography.
- Validate all API inputs.
- Prefer credential references + fingerprints over copying full credential data.

## Pull Requests

- Keep PRs focused on a single concern.
- Describe what changed and why.
- Mention any tests written and their results.
- Reference related issues.
- Request at least one review.

## Secret Handling

1. Add secrets to `scripts/setup_env.sh` or document them in `.env.example` with placeholders.
2. Never add real `.env` files to the repository — the `.gitignore` excludes them.
3. If you discover a leaked secret, revoke it immediately and report it.

## Ownership

This repository is owned and primarily maintained by **Savan**. Other team members are welcome to review and test. For significant architectural changes, coordinate with the owner first.
