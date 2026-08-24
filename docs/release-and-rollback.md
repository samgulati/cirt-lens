# Release, verification, and rollback

Tagged releases build one immutable GHCR image. The release workflow publishes an SPDX SBOM, GitHub build-provenance attestation, and keyless Sigstore signature for the exact image digest. Deployments should use the digest, not a mutable tag.

Before release, require green backend tests, migration validation, the 360-case evaluation gate, scale guardrails, frontend formatting/lint/component/build checks, Playwright workflows, dependency audit, secret scan, and container vulnerability gate.

## Database-safe rollout

1. Back up PostgreSQL and record the currently deployed image digest.
2. Run `alembic upgrade head` as a release task before switching traffic.
3. Deploy the new digest, then verify `/health/live`, `/health/ready`, `/metrics`, login, incident reads, and one dry-run connector action.
4. Monitor HTTP error rate, ingestion queue/DLQ depth, worker completion, connector failures, and approval latency.

## Rollback

Application rollback means redeploying the recorded prior digest. Prefer forward-compatible migrations and an application rollback without a schema downgrade. If the release has not written data requiring the new schema and a database rollback is explicitly approved, run `alembic downgrade -1` only after restoring/validating the backup in an isolated environment. Never delete the production database to roll back.
