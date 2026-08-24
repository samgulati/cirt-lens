#!/usr/bin/env python3
"""Bounded HTTP load profile for the real API, Redis stream, worker, and database."""

import argparse
import asyncio
import json
import math
import statistics
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1)]


def event(sequence: int) -> dict:
    return {
        "id": f"LOAD-{uuid.uuid4().hex[:16].upper()}",
        "timestamp": datetime.now(UTC).isoformat(),
        "schema_version": "1.0",
        "telemetry_type": "network",
        "source_ip": f"10.20.{sequence % 250}.{(sequence * 7) % 250 + 1}",
        "destination_ip": "203.0.113.40",
        "destination_port": 443,
        "protocol": "TCP",
        "bytes_sent": 4096 + sequence,
        "bytes_received": 1024,
        "domain": "load-test.example",
        "country": "US",
        "user": f"load-{sequence % 40}@example.com",
        "hostname": f"LOAD-HOST-{sequence % 80:03d}",
    }


async def run(base_url: str, requests: int, concurrency: int, events_per_request: int) -> dict:
    semaphore = asyncio.Semaphore(concurrency)
    latencies: list[float] = []
    jobs: list[str] = []
    errors: list[str] = []
    started = time.perf_counter()
    timeout = httpx.Timeout(30)
    async with httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout) as client:

        async def submit(index: int):
            async with semaphore:
                payload = {
                    "events": [
                        event(index * events_per_request + offset)
                        for offset in range(events_per_request)
                    ]
                }
                before = time.perf_counter()
                response = await client.post(
                    "/api/telemetry/ingest",
                    json=payload,
                    headers={"Idempotency-Key": f"load-{uuid.uuid4()}"},
                )
                latencies.append((time.perf_counter() - before) * 1000)
                if response.status_code != 202:
                    errors.append(f"{response.status_code}:{response.text[:120]}")
                else:
                    jobs.append(response.json()["job_id"])

        await asyncio.gather(*(submit(index) for index in range(requests)))
        submission_seconds = time.perf_counter() - started
        deadline = time.monotonic() + 60
        states: dict[str, str] = {}
        while jobs and time.monotonic() < deadline:
            responses = await asyncio.gather(
                *(client.get(f"/api/telemetry/jobs/{job}") for job in jobs)
            )
            states = {
                job: (
                    response.json().get("status", "HTTP_ERROR")
                    if response.is_success
                    else "HTTP_ERROR"
                )
                for job, response in zip(jobs, responses, strict=True)
            }
            if all(state in {"COMPLETED", "FAILED", "DEAD_LETTER"} for state in states.values()):
                break
            await asyncio.sleep(0.25)
        duplicate = None
        if requests:
            key = f"dedupe-{uuid.uuid4()}"
            payload = {"events": [event(requests * events_per_request + 1)]}
            await client.post(
                "/api/telemetry/ingest", json=payload, headers={"Idempotency-Key": key}
            )
            duplicate = (
                (
                    await client.post(
                        "/api/telemetry/ingest", json=payload, headers={"Idempotency-Key": key}
                    )
                )
                .json()
                .get("deduplicated")
            )

    total_seconds = time.perf_counter() - started
    completed = sum(state == "COMPLETED" for state in states.values())
    return {
        "profile": {
            "requests": requests,
            "concurrency": concurrency,
            "events_per_request": events_per_request,
        },
        "submitted_events": requests * events_per_request,
        "submission_rps": round(requests / submission_seconds, 2),
        "event_throughput_per_second": round((completed * events_per_request) / total_seconds, 2),
        "latency_ms": {
            "mean": round(statistics.mean(latencies), 2),
            "p50": round(percentile(latencies, 0.50), 2),
            "p95": round(percentile(latencies, 0.95), 2),
            "p99": round(percentile(latencies, 0.99), 2),
        },
        "completed_jobs": completed,
        "terminal_states": dict(
            sorted(
                {
                    state: list(states.values()).count(state) for state in set(states.values())
                }.items()
            )
        ),
        "error_count": len(errors),
        "sample_errors": errors[:5],
        "idempotency_verified": duplicate is True,
        "duration_seconds": round(total_seconds, 2),
        "scope": "Local Docker HTTP + PostgreSQL + Redis Streams + background worker; not production capacity.",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--events-per-request", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = asyncio.run(
        run(args.base_url, args.requests, args.concurrency, args.events_per_request)
    )
    rendered = json.dumps(result, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n")
    if (
        result["error_count"]
        or result["completed_jobs"] != args.requests
        or not result["idempotency_verified"]
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
