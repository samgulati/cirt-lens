# Performance notes

The suspicious-correlation benchmark contains 5,000 unrelated noise events plus 20 four-event suspicious clusters. It executes production candidate generation, edge scoring, all-pairs cohesion, and connected-component grouping.

```bash
cd backend
PYTHONPATH=. python benchmarks/correlation_benchmark.py
```

Measured in the Docker API image on 21 August 2026:

| Events | All possible pairs | Candidates | Accepted edges | Groups | Elapsed |
|---:|---:|---:|---:|---:|---:|
| 5,080 | 12,900,660 | 120 | 120 | 20 | 27.95 ms |

Entity buckets reduced comparisons by 99.9991% for this constructed workload and recovered all 20 planted groups. This is a reproducible algorithm check, not a throughput guarantee; results vary by hardware/workload and exclude validation, HTTP, persistence, and rendering.
