# CIRT Lens

[![CI](https://github.com/samgulati/cirt-lens/actions/workflows/ci.yml/badge.svg)](https://github.com/samgulati/cirt-lens/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/samgulati/cirt-lens?display_name=tag)](https://github.com/samgulati/cirt-lens/releases)

Public staging: **[cirt-lens.onrender.com](https://cirt-lens.onrender.com)**

## Engineering-hardening highlights

- Incremental ingestion queries bounded historical context, so later events can detect and enrich an existing incident across requests.
- Versioned detection findings and event schemas are first-class database records.
- Trusted device baselines are immutable during attack processing; observing a failed or suspicious login cannot silently trust its device.
- Temporal privilege findings require a same-user suspicious authentication that occurred earlier and inside the configured window.
- Risk and evidence confidence (`/100`, not probability) have separate named breakdowns; points require supporting evidence.
- Incident fingerprints, cohesion/span guardrails, case notes, evidence bookmarks, dispositions, containment objectives, and residual-risk history support an auditable lifecycle.
- Structured AI claims require non-empty incident evidence IDs; malformed external output retries once and falls back locally.
- Alembic owns schema upgrades. Docker runs `alembic upgrade head` before starting the API.
- PostgreSQL is the operational store; Redis Streams and a separate worker provide asynchronous, idempotent ingestion with retry and dead-letter handling.
- Signed local JWT authentication, cryptographically verified OIDC JWT support, tenant scoping, four RBAC roles, and two-person approval protect high-impact actions.
- OpenTelemetry instrumentation, Prometheus, a provisioned Grafana dashboard, structured logs, dependency readiness, an evaluation dataset, and CI/release pipelines make the system operable.
- A tenant-scoped operator control plane exposes two-person approvals, ingestion jobs and DLQ health, connector execution history, and provider reconciliation without exposing telemetry payloads.
- High-impact approvals expire after 30 minutes and are atomically consumed on execution; Auth0 calls have classified retries, backoff, circuit breaking, allowlisting, dry-run, stable idempotency, and reconciliation.
- Release images are vulnerability-scanned, keyless-signed, accompanied by an SPDX SBOM, and linked to GitHub build-provenance attestations; third-party Actions are pinned to immutable SHAs.
- The React frontend is split into lazy-loaded route pages, shared layout/common components, and investigation components; the initial production chunk is 245 KB (78.9 KB gzip).
- Three Playwright workflows cover credential and endpoint compromise plus mobile operator failure recovery, including case work, AI grounding, ATT&CK evidence, response simulation, request-ID supportability, and audit verification with a clean browser console.
- See the [security model](docs/security-model.md) and [performance notes](docs/performance.md).

For native backend startup, run migrations first:

```bash
cd backend
alembic upgrade head
uvicorn app.main:app --reload
```
CIRT Lens is a polished, locally runnable security incident triage and response workbench. It correlates realistic synthetic identity, endpoint, network, and cloud telemetry into evidence-backed investigations with transparent scoring, forensic timelines, simplified MITRE ATT&CK mappings, safe SOAR simulations, and a grounded investigation assistant.

## Problem

Security teams receive alerts from many systems, making it difficult to reconstruct an attack quickly. Analysts must connect identities, devices, IPs, cloud actions, and time before they can make a defensible response decision.

## Solution

CIRT Lens turns multi-source telemetry into coherent investigations and gives analysts a fast path from detection to evidence review, containment, and reporting. Everything is synthetic and response actions are simulations.

## Architecture

```mermaid
flowchart TD
  A[Synthetic Raw Telemetry] --> B[Pydantic Validation]
  B --> Q[PostgreSQL Ingestion Job]
  Q --> R[Redis Stream]
  R --> C[Background Detection Worker]
  C --> D[Event Findings + Risk]
  D --> E[Correlation Engine]
  E --> F[Incident Classification]
  F --> G[Risk Engine]
  G --> H[ATT&CK Mapping]
  H --> I[Playbook Engine]
  I --> J[Investigation UI]
  J --> K[AI Investigator]
  J --> L[Response Simulation]
  N[Auth0 OIDC + Tenant RBAC] --> J
  L --> O[Two-person Approval]
  O --> P[Allowlisted Connector + Reconciliation]
  K --> M[Audit Trail]
  L --> M
```

The React/Vite frontend talks to a FastAPI API backed by PostgreSQL. Redis Streams decouples ingestion from a detection/correlation worker; SQLite remains available only as a zero-dependency test/development profile. Scenario selection supplies raw observations only; it cannot set findings, incident type, risk, confidence, ATT&CK techniques, or playbooks. See [architecture notes](docs/architecture.md) and the [production platform extension](docs/production-platform.md).

## Features

- SOC overview with operational KPIs, trends, severity, detection sources, and incident queue
- 300+ seeded events, 30+ suspicious observations, four users, five hosts, and three built-in attack investigations
- One-click credential compromise, endpoint compromise, and exfiltration demo generation
- Incident centerpiece with overview, expandable timeline, evidence, ATT&CK, response, and AI tabs
- Analyst Case workspace with disposition, notes, evidence bookmarks, and residual-risk history
- Entity-aware threat hunting (`user:`, `host:`, `ip:`, `flag:`)
- Keyboard-accessible global entity search and an evidence-derived entity graph
- Confirmed simulated SOAR execution and auditable activity log
- Immutable original risk with deterministic residual-risk reduction
- Downloadable Markdown incident reports
- Loading, error-safe empty states, confirmations, filters, and responsive charts
- Operator control plane for approval inbox, queue/DLQ health, job visibility, connector history, and reconciliation
- Request-ID-aware failure messages, keyboard focus treatment, skip navigation, responsive mobile navigation, and role-aware controls

## Detection Logic

Deterministic rules detect impossible travel, four MFA denials inside ten minutes, new devices, suspicious PowerShell strings, structured credential access, destinations in a synthetic documentation-range intelligence set, unusual egress, persistence, sensitive resources, and privileged actions. Rules produce explainable findings containing event ID, rule ID, flag, contribution, reason, and metadata. Command lines are inert strings and are never executed.

## Why deterministic detection?

The project prioritizes explainability, reproducibility, and interview-defensible behavior over black-box anomaly detection. Thresholds are configurable through environment variables.

## Risk Scoring

Risk is an explainable 0–100 sum: event evidence (0–40), asset criticality (0–20), behavioral anomaly (0–20), and threat intelligence (0–20). Severity is Low (0–24), Medium (25–49), High (50–74), or Critical (75–100). Every incident exposes its full contribution breakdown.

The stored breakdown sum is guaranteed to equal original risk. Original risk is immutable. Executed simulated actions reduce a separate residual-risk score using documented demonstration reductions.

## Correlation

Suspicious events are connected using an in-memory adjacency list. Candidate buckets avoid comparing unrelated events globally. Shared users/hosts, devices/IPs, source/destination overlap, and temporal proximity contribute explainable edge scores. Weak edges, low-cohesion groups, single-signal groups, and excessive incident spans are rejected. Deterministic fingerprints make reprocessing idempotent while allowing open incidents to be enriched with later evidence.

## AI Grounding

Without an API key, the question-aware deterministic investigator answers using incident evidence. External output must be structured JSON with evidence IDs for every factual claim; IDs must belong to the current incident. Invalid output triggers one retry and then local fallback. This validates evidence ownership and structure, not the truth of a model interpretation. Secrets never reach the browser.

## Why a modular monolith?

Detection, correlation, risk, mapping, playbook, AI, generation, and serialization have clear module boundaries while deployment remains one backend process. That preserves maintainability without premature distributed-system overhead.

## Why synthetic telemetry?

PostgreSQL provides indexed operational persistence while synthetic telemetry makes the public demonstration safe and repeatable without exposing enterprise security or personal data. OpenSearch is intentionally not required for this portfolio-sized dataset; the connector boundary allows it to be added when query volume justifies another datastore.

## Why simulated SOAR?

Real containment requires vendor integrations, scoped authorization, approvals, idempotency, rollback, and blast-radius controls. CIRT Lens demonstrates decision and audit semantics without claiming those integrations exist.

## Running Locally

### Docker

```bash
docker compose up --build
```

Open `http://localhost:5173`. API docs are at `http://localhost:8000/docs`.

Operational views: Prometheus at `http://localhost:9090` and Grafana at `http://localhost:3001` (anonymous local viewer). The API and background worker use PostgreSQL and Redis automatically.

### Native development

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

## Running Tests

```bash
cd backend
pytest
```

The 62-test backend suite covers positive and negative detection boundaries, a cross-resource tenant isolation matrix, RBAC, unauthorized action denial, approval expiry/consumption, connector retries/circuit breaking/reconciliation, ingestion idempotency, rule lifecycle/replay, cross-batch enrichment, rollback, hostile-string safety, correlation cohesion, scoring, grounded AI output, and Alembic upgrades. Four Vitest component tests cover role-derived controls and request-ID/network failure contracts.

From `backend`, run `PYTHONPATH=. python evaluation/run_evaluation.py` for the 360-case labeled quality gate: 120 malicious chains and 240 benign/near-threshold negatives, reported across train/development/test partitions and with every third case delivered out of order. It enforces minimum precision, recall, classification, correlation, and grounding scores. Run `PYTHONPATH=. python benchmarks/benchmark_pipeline.py` and `PYTHONPATH=. python benchmarks/correlation_benchmark.py` for deterministic 10,000-event pipeline and 5,080-event correlation guardrails. Run the [end-to-end load profile](load-tests/README.md) to measure the HTTP, PostgreSQL, Redis Streams, and worker path. These synthetic measurements demonstrate regression resistance; they are not claims about real-world detection efficacy or production capacity. Run `npm test` and `npm run test:e2e` in `frontend` for component and Playwright workflows.

## Verified engineering evidence

The following was reproduced locally on 24 August 2026; hardware and environment materially affect performance:

| Evidence | Result |
| --- | --- |
| Backend suite | 62 passed |
| Frontend component suite | 4 passed |
| Labeled evaluation | 360/360 cases; 1.00 synthetic precision and recall |
| Pipeline guardrail | 10,000 validated/detected events in 44.11 ms (in-process) |
| Correlation guardrail | 5,080 events in 27.64 ms; candidate pruning reduced comparisons 99.9991% |
| End-to-end Docker profile | 1,000 events; 100/100 jobs completed; 0 errors; p95 ingest latency 119.19 ms; 556.81 processed events/s |

See [operational evidence](docs/operations-evidence.md), [performance methodology](docs/performance.md), and [release/rollback](docs/release-and-rollback.md) for scope and reproduction commands.

## Two-Minute Demo

1. Open the overview and select **Generate Demo Incident**.
2. Choose **Credential Compromise** and generate it.
3. Review the critical score breakdown and reconstructed timeline.
4. Expand raw evidence and inspect simplified ATT&CK mappings.
5. Ask “What probably happened?” in AI Investigator.
6. As a Responder, request “Revoke active sessions”; approve it as a different Administrator, then execute it as the Responder.
7. Add a case note, disposition, and evidence bookmark, then inspect risk history.
8. Export the Markdown report.

## Design Tradeoffs

- Synthetic telemetry keeps the project safe and reproducible instead of depending on enterprise integrations.
- Transparent rules demonstrate investigation logic without pretending to provide production anomaly detection.
- SQLite keeps the default local setup immediate; PostgreSQL is used by the public staging blueprint.
- Most SOAR actions use a deterministic fake connector. Only the allowlisted Auth0 development-tenant `Disable account` action can use the live sandbox connector, and it remains approval-gated.
- ATT&CK mappings are intentionally simplified demonstration mappings, not authoritative classifications.

## Public environment

The staging deployment uses TLS, Auth0 OIDC, four role-specific demo identities, PostgreSQL, Redis-backed asynchronous ingestion, and an allowlisted Auth0 development-tenant Management API connector. Most response actions deliberately remain deterministic dry-runs; only account disablement can reach the isolated Auth0 sandbox target. Credentials and tenant configuration are environment-owned and never committed.

## Engineering Documentation

- [Architecture deep dive](docs/architecture.md)
- [Security model](docs/security-model.md)
- [Production platform](docs/production-platform.md)
- [Performance notes](docs/performance.md)
- [Operational evidence and runbooks](docs/operations-evidence.md)
- [Release and rollback](docs/release-and-rollback.md)

Schema changes are managed through Alembic. Existing local and Docker databases should be upgraded with `alembic upgrade head`; deleting the database is only appropriate when the user explicitly wants a fresh synthetic environment.

## Final product

![CIRT Lens dashboard](docs/final-product.png)
