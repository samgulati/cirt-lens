# Production platform extension

## Implemented locally

- Local PBKDF2-backed identities and signed JWT sessions; OIDC mode verifies issuer, audience, expiry, algorithm, and signatures through a configured JWKS URL.
- Tenant IDs and enforced query boundaries on identities, events, incidents, approvals, ingestion jobs, rule versions, connector executions, search, reports, and audit activity.
- Viewer, analyst, responder, and administrator role hierarchy enforced by API dependencies.
- Time-bound, single-use two-person authorization for high-impact response actions when `AUTH_REQUIRED=true`.
- Redis Streams ingestion with durable job status, tenant-scoped idempotency keys, retry accounting, consumer acknowledgements, and a dead-letter stream.
- PostgreSQL operational storage, tenant/timestamp indexes, cursor pagination, dry-run-first retention tooling, and Alembic migrations.
- Versioned detection-rule catalog with draft, testing, active, and retired states plus non-mutating historical replay.
- Replaceable response connector contract, deterministic fake identity connector, and allowlisted Auth0 development-tenant connector with dry-run, classified retry/backoff, circuit breaking, idempotency/provider request IDs, history, and reconciliation.
- OpenTelemetry request traces, Prometheus metrics, Grafana provisioning, structured request logs, request/incident IDs, and database/Redis readiness.
- A 360-case deterministic labeled evaluation corpus with 120 malicious and 240 benign/near-threshold cases, train/development/test reporting, and reversed delivery-order coverage; CI-enforced precision, recall, classification/correlation, and AI evidence-grounding thresholds.
- Reproducible 10,000-event pipeline and 5,080-event correlation guardrails with candidate-pair reduction and expected-group checks.
- CI for formatting, linting, targeted static typing, migrations, 62 backend tests, evaluation and scale guardrails, frontend component/build/Playwright tests, dependency and secret audit, image build, and Trivy scanning. Tagged releases publish a keyless-signed GHCR image with SPDX SBOM and provenance attestation.

## Local accounts

All local users use `DemoPass!2026`: `viewer@demo.local`, `analyst@demo.local`, `responder@demo.local`, and `admin@demo.local`. These credentials are demonstration fixtures and must never be used outside local development.

## Public staging configuration

The public TLS staging URL uses an Auth0 development tenant and managed PostgreSQL/Redis. Credentials, allowlists, and provider identifiers are environment-owned and deliberately excluded from Git. The repository makes no claim that this free staging topology has production availability or capacity.

## Delivery semantics

Redis Streams provides at-least-once delivery. The tenant/idempotency-key uniqueness constraint prevents duplicate jobs, event IDs make persistence idempotent, workers acknowledge only after commit, and failed jobs become retryable before reaching the DLQ. Entity-local ordering is preserved within a stream consumer; a scaled deployment should partition streams by tenant/entity when strict per-principal ordering is required.
