# Operational evidence and incident runbooks

This page distinguishes reproducible evidence from design intent. It contains no credentials, production telemetry, or personal data.

## Reproduced evidence — 24 August 2026

| Layer | Command | Observed result |
| --- | --- | --- |
| API correctness | `PYTHONPATH=backend backend/.venv/bin/pytest -q backend/tests` | 62 passed |
| Detection quality | `PYTHONPATH=backend backend/.venv/bin/python backend/evaluation/run_evaluation.py` | 360/360 synthetic cases passed; 120 TP, 240 TN, 0 FP, 0 FN |
| Pipeline guardrail | `PYTHONPATH=backend backend/.venv/bin/python backend/benchmarks/benchmark_pipeline.py` | 10,000 events in 44.11 ms in-process |
| Correlation guardrail | `PYTHONPATH=backend backend/.venv/bin/python backend/benchmarks/correlation_benchmark.py` | 5,080 events in 27.64 ms; 120 candidate pairs vs 12,900,660 all-pairs |
| Full ingestion path | `backend/.venv/bin/python load-tests/run_profile.py --requests 100 --concurrency 10 --events-per-request 10` | 1,000 events, 100/100 completed jobs, 0 errors, p50 45.57 ms, p95 119.19 ms, p99 136.28 ms, 556.81 processed events/s |

The first two performance tools are deterministic in-process regression guards. The full ingestion profile traverses HTTP validation, PostgreSQL, Redis Streams, and the worker on a local Docker environment. None is a production capacity or real-world detection-efficacy claim.

## Dashboard and query evidence

Prometheus scrapes `/metrics`; Grafana is provisioned from `ops/grafana`. Useful queries include:

- API p95: `histogram_quantile(0.95, sum(rate(cirt_http_request_seconds_bucket[5m])) by (le, path))`
- Detection p95: `histogram_quantile(0.95, rate(cirt_detection_seconds_bucket[5m]))`
- Approval transitions: `sum by (status) (rate(cirt_action_approvals_total[5m]))`
- Connector failures: `sum by (connector, code, retryable) (rate(cirt_connector_failures_total[5m]))`
- Queue and dead-letter depth: `cirt_ingestion_queue_depth` and `cirt_ingestion_dlq_depth`

Every API response includes `x-request-id`; structured logs include the same ID with path, status, and latency. Connector executions preserve the provider request ID for reconciliation.

## Drill: Redis unavailable

1. Confirm readiness reports Redis unavailable and ingestion returns 503 rather than accepting untracked work.
2. Correlate the client-visible request ID with structured API logs.
3. Restore Redis, verify readiness, and retry with the same idempotency key.
4. Confirm one job exists and `deduplicated=true` on repeated delivery.

## Drill: dead-letter growth

1. Alert when `cirt_ingestion_dlq_depth > 0` for five minutes.
2. Use the Operations page to inspect failed job IDs and redacted error summaries.
3. Correct the dependency/schema cause; replay only explicitly selected jobs with their original idempotency key.
4. Verify completed state and queue/DLQ recovery; record the request and job IDs in the incident timeline.

## Drill: connector degradation

1. Observe classified connector errors (`NETWORK`, `UPSTREAM_RETRYABLE`, `UPSTREAM_REJECTED`, or `CIRCUIT_OPEN`).
2. Leave the response action unexecuted when the connector fails; its approval is consumed only in the successful transaction.
3. Wait for the circuit recovery window, use the Operations page to reconcile provider state, and retry only if the stored provider request ID proves no success occurred.
4. Keep live execution restricted to the allowlisted development-tenant identity; use dry-run for every other target/action.
