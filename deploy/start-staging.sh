#!/bin/sh
set -eu

python -m alembic upgrade head
python -m app.worker &
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-10000}"
