# Production platform extension

## Implemented locally

- Local PBKDF2-backed identities and signed JWT sessions; OIDC mode verifies issuer, audience, expiry, algorithm, and signatures through a configured JWKS URL.
- Tenant IDs on identities, events, incidents, approvals, connector executions, and audit activity.
- Viewer, analyst, responder, and administrator role hierarchy enforced by API dependencies.
- Two-person authorization for high-impact response actions when `AUTH_REQUIRED=true`.
- Redis Streams ingestion with durable job status, tenant-scoped idempotency keys, retry accounting, consumer acknowledgements, and a dead-letter stream.
- PostgreSQL operational storage, tenant/timestamp indexes, cursor pagination, dry-run-first retention tooling, and Alembic migrations.
- Versioned detection-rule catalog with draft, testing, active, and retired states plus non-mutating historical replay.
- Replaceable response connector contract and deterministic fake identity connector preserving idempotency/provider request IDs.
- OpenTelemetry request traces, Prometheus metrics, Grafana provisioning, structured request logs, request/incident IDs, and database/Redis readiness.
- Versioned positive and benign evaluation cases reporting a confusion matrix, precision, recall, classification/correlation accuracy, and AI evidence-grounding validation.
- CI for migrations, backend tests, evaluation, frontend build, Playwright, dependency audit, image build, and Trivy scanning. Tagged releases publish a versioned GHCR image.

## Local accounts

All local users use `DemoPass!2026`: `viewer@demo.local`, `analyst@demo.local`, `responder@demo.local`, and `admin@demo.local`. These credentials are demonstration fixtures and must never be used outside local development.

## External configuration

A real OIDC tenant, managed PostgreSQL/Redis endpoints, a public DNS/TLS environment, and a real response provider require user-owned credentials. Kubernetes manifests and environment boundaries are supplied, but the repository does not claim those external resources are deployed.

## Delivery semantics

Redis Streams provides at-least-once delivery. The tenant/idempotency-key uniqueness constraint prevents duplicate jobs, event IDs make persistence idempotent, workers acknowledge only after commit, and failed jobs become retryable before reaching the DLQ. Entity-local ordering is preserved within a stream consumer; a scaled deployment should partition streams by tenant/entity when strict per-principal ordering is required.
