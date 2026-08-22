# Contributing

## Development setup

The supported full-stack path is:

```bash
docker compose up --build
```

Open the application at `http://localhost:5173` and the API documentation at `http://localhost:8000/docs`.

## Required checks

Before opening a pull request, run:

```bash
cd backend
pytest -q
PYTHONPATH=. python evaluation/run_evaluation.py

cd ../frontend
npm ci
npm run build
npm run test:e2e
```

Schema changes require an Alembic migration. Security-sensitive changes should include negative authorization tests. Detection changes should include positive, negative, boundary, duplicate-delivery, and replay coverage where applicable.

## Pull requests

- Keep changes focused and explain the problem, design, tradeoffs, and verification.
- Do not commit secrets, real telemetry, personal information, generated reports, or local databases.
- Preserve deterministic and evidence-backed behavior.
- Document new configuration in `.env.example` without including real values.
- Treat external response actions as dry-run by default and explicitly bounded when live.

By contributing, you confirm that your contribution does not contain confidential or third-party restricted data.
