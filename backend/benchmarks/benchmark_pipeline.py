"""Reproducible, non-production benchmark for bounded CIRT Lens pipeline stages."""
from datetime import datetime,timedelta
from pathlib import Path
import sys,time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.schemas.telemetry import AuthenticationEventInput
from app.services.detection_engine import run_detection
from app.services.correlation_engine import connected_groups
from app.models import Event

def events(count):
    start=datetime(2026,1,1)
    return [AuthenticationEventInput(id=f"BENCH-{i}",timestamp=start+timedelta(seconds=i),user=f"user{i%250}@example.test",source_ip=f"10.{i%250}.{(i//250)%250}.1",country="India",city="Delhi",device_id=f"TRUST-{i%250}",result="SUCCESS",mfa_result="APPROVED",authentication_method="FIDO2") for i in range(count)]
def run(count):
    t=time.perf_counter();raw=events(count);validation=time.perf_counter()-t
    t=time.perf_counter();findings=run_detection(raw,{f"user{i}@example.test":{f"TRUST-{i}"} for i in range(250)});detection=time.perf_counter()-t
    suspicious=[Event(id=f.event_id,timestamp=raw[int(f.event_id.split('-')[1])].timestamp,source="Identity",user=raw[int(f.event_id.split('-')[1])].user,host=None,source_ip=None,activity="benchmark",risk_score=10,risk_flags=f'["{f.flag}"]',data="{}") for f in findings[:500]]
    t=time.perf_counter();connected_groups(suspicious);correlation=time.perf_counter()-t
    return validation,detection,correlation
if __name__=="__main__":
    print("events,validation_ms,detection_ms,correlation_ms,total_ms")
    failed=False
    for count in (1000,5000,10000):
        values=run(count);total=sum(values);print(f"{count},"+",".join(f"{x*1000:.2f}" for x in (*values,total)))
        if count==10000 and total>5:failed=True
    if failed:raise SystemExit("10,000-event in-process benchmark exceeded the 5-second CI guardrail")
