"""Redis Streams consumer with retries, pending recovery and dead-letter handling."""
import json,time
from datetime import datetime,UTC
from redis import Redis
from .config import settings
from .database import SessionLocal
from .models import IngestionJob
from .schemas.telemetry import TelemetryInput
from pydantic import TypeAdapter
from .services.pipeline import process_raw_telemetry
from .seed.seed_data import BASELINE_DEVICES
from .observability import INGESTION,DLQ_DEPTH

GROUP="cirt-workers";CONSUMER="worker-1"
def now():return datetime.now(UTC).replace(tzinfo=None)
def run_once(redis_client=None):
    client=redis_client or Redis.from_url(settings.redis_url,decode_responses=True)
    try:client.xgroup_create(settings.telemetry_stream,GROUP,id="0",mkstream=True)
    except Exception:pass
    messages=client.xreadgroup(GROUP,CONSUMER,{settings.telemetry_stream:">"},count=10,block=1000)
    for _,items in messages:
        for stream_id,payload in items:
            db=SessionLocal();job=db.get(IngestionJob,payload["job_id"])
            try:
                if not job:client.xack(settings.telemetry_stream,GROUP,stream_id);continue
                job.status="PROCESSING";job.attempts+=1;job.updated_at=now();db.commit();events=TypeAdapter(list[TelemetryInput]).validate_python(json.loads(payload["events"]));process_raw_telemetry(db,events,BASELINE_DEVICES,tenant_id=payload["tenant_id"]);job=db.get(IngestionJob,job.id);job.status="COMPLETED";job.updated_at=now();db.commit();client.xack(settings.telemetry_stream,GROUP,stream_id);INGESTION.labels("COMPLETED").inc()
            except Exception as exc:
                db.rollback();job=db.get(IngestionJob,payload["job_id"])
                if job:job.error=str(exc)[:1000];job.updated_at=now();job.status="DEAD_LETTER" if job.attempts>=settings.max_processing_attempts else "RETRYING";db.commit()
                if job and job.status=="DEAD_LETTER":client.xadd(settings.telemetry_dlq,{**payload,"error":job.error});client.xack(settings.telemetry_stream,GROUP,stream_id);INGESTION.labels("DEAD_LETTER").inc()
                elif job:client.xadd(settings.telemetry_stream,payload);client.xack(settings.telemetry_stream,GROUP,stream_id);INGESTION.labels("RETRYING").inc()
            finally:db.close()
    try:DLQ_DEPTH.set(client.xlen(settings.telemetry_dlq))
    except Exception:pass
    return sum(len(items) for _,items in messages)
def main():
    while True:
        try:run_once()
        except Exception:time.sleep(2)
if __name__=="__main__":main()
