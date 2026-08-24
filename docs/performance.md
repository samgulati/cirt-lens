# Performance notes

The suspicious-correlation benchmark contains 5,000 unrelated noise events plus 20 four-event suspicious clusters. It executes production candidate generation, edge scoring, all-pairs cohesion, and connected-component grouping.

```bash
cd backend
PYTHONPATH=. python benchmarks/correlation_benchmark.py
```

Reproduced locally on 24 August 2026:

| Events | All possible pairs | Candidates | Accepted edges | Groups | Elapsed |
|---:|---:|---:|---:|---:|---:|
| 5,080 | 12,900,660 | 120 | 120 | 20 | 27.64 ms |

Entity buckets reduced comparisons by 99.9991% for this constructed workload and recovered all 20 planted groups. This is a reproducible algorithm check, not a throughput guarantee; results vary by hardware/workload and exclude validation, HTTP, persistence, and rendering.

## Full ingestion profile

`load-tests/run_profile.py` exercises HTTP validation, PostgreSQL job persistence, Redis Streams, the background worker, and completion polling. A bounded local Docker run submitted 100 requests × 10 events at concurrency 10: 100/100 jobs completed with zero request errors, p50/p95/p99 submission latency of 45.57/119.19/136.28 ms, and 556.81 processed events/s over the measured interval. Idempotent duplicate delivery was verified. This single-machine synthetic result is regression evidence, not a staging SLO or production capacity claim.
