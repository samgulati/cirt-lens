# End-to-end load profile

This profile measures the deployed request path rather than an in-process algorithm: FastAPI validation, PostgreSQL job persistence, Redis Streams delivery, the background worker, detection/correlation, and job completion.

```bash
docker compose up --build -d
backend/.venv/bin/python load-tests/run_profile.py --requests 100 --concurrency 10 --events-per-request 10
```

Use `--output load-tests/results/local.json` to retain a local artifact (results are intentionally gitignored). The command fails when requests fail, jobs do not complete within 60 seconds, or idempotency is broken. Run only against infrastructure you own; the default is localhost. These bounded synthetic results are regression evidence, not a claim about internet-scale production capacity.
