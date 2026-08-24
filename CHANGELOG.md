# Changelog

All notable changes are recorded here. Releases follow semantic versioning.

## Unreleased

## 1.1.0 - 2026-08-24

- Added a tenant-scoped operations control plane for approval, ingestion, DLQ, and connector reconciliation workflows.
- Made high-impact approvals expire after 30 minutes and become atomically consumed after successful execution.
- Added tenant ownership to versioned detection rules and expanded isolation tests across operational resources.
- Added connector retry classification, exponential backoff, circuit breaking, execution history, and reconciliation.
- Expanded the labeled deterministic evaluation from 36 to 360 cases with train/development/test reporting and out-of-order delivery.
- Added an end-to-end HTTP/PostgreSQL/Redis/worker load profile and frontend authorization/error component tests.
- Added Black, Ruff, MyPy, ESLint, Prettier, secret scanning, SBOM generation, provenance attestations, and keyless container signing.

## 1.0.0

- First interview-ready release with Auth0 OIDC/RBAC, tenant isolation, asynchronous ingestion, versioned rules, approval-gated response actions, observability, CI, and public staging.
