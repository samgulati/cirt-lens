import json,logging
import time
from collections import defaultdict
from datetime import timedelta,datetime,UTC
from sqlalchemy import or_
from ..config import settings
from ..models import Event,DetectionFindingRecord
from ..schemas.telemetry import AuthenticationEventInput,EndpointEventInput,NetworkEventInput,CloudEventInput
from .detection_engine import run_detection
from .correlation_engine import create_or_update_incidents
from ..observability import DETECTION_LATENCY,CORRELATION_GROUPS

log=logging.getLogger("cirt.pipeline")
SCHEMA_BY_TYPE={"authentication":AuthenticationEventInput,"endpoint":EndpointEventInput,"network":NetworkEventInput,"cloud":CloudEventInput}

def normalize(raw,tenant_id="tenant-demo"):
    data=raw.model_dump(mode="json")
    if isinstance(raw,AuthenticationEventInput):source="Identity";host=raw.device_id;activity=f"{raw.result.title()} authentication — {raw.city}, {raw.country}"
    elif isinstance(raw,EndpointEventInput):source="Endpoint";host=raw.hostname;activity={"PROCESS_START":f"Process started: {raw.process_name}","CREDENTIAL_STORE_ACCESS":"Credential store access attempted","RUN_KEY_MODIFICATION":"Run key persistence modified"}.get(raw.event_type,raw.event_type.replace('_',' ').title())
    elif isinstance(raw,NetworkEventInput):source="Network";host=raw.hostname;activity=f"{raw.protocol} connection to {raw.destination_ip}:{raw.destination_port} — {raw.bytes_sent:,} bytes sent"
    else:source="Cloud";host=raw.device_id;activity=f"{raw.service}: {raw.action} on {raw.resource}"
    return Event(id=raw.id,tenant_id=tenant_id,timestamp=raw.timestamp,source=source,user=getattr(raw,"user",None),host=host,source_ip=getattr(raw,"source_ip",None),activity=activity,risk_score=0,risk_flags="[]",data=json.dumps(data),schema_version=raw.schema_version)

def typed_from_event(event):
    data=json.loads(event.data);kind=data.get("telemetry_type");model=SCHEMA_BY_TYPE.get(kind)
    if not model:return None
    data={k:v for k,v in data.items() if k!="detection_findings"}
    try:return model.model_validate(data)
    except Exception:return None

def historical_context(db,raw_events,tenant_id="tenant-demo"):
    if not raw_events:return []
    earliest=min(e.timestamp for e in raw_events);newest=max(e.timestamp for e in raw_events);lookback=max(settings.correlation_window_minutes,settings.impossible_travel_window_minutes,settings.privileged_action_after_auth_window_minutes,settings.mfa_fatigue_window_minutes);start=earliest-timedelta(minutes=lookback)
    users={getattr(e,"user",None) for e in raw_events}-{None};hosts={getattr(e,"hostname",None) for e in raw_events}-{None};ips={getattr(e,"source_ip",None) for e in raw_events}-{None};destination_ips={getattr(e,"destination_ip",None) for e in raw_events}-{None};devices={getattr(e,"device_id",None) for e in raw_events}-{None}
    clauses=[]
    if users:clauses.append(Event.user.in_(users))
    if hosts or devices:clauses.append(Event.host.in_(hosts|devices))
    if ips:clauses.append(Event.source_ip.in_(ips))
    for destination_ip in destination_ips: clauses.append(Event.data.contains(destination_ip))
    if not clauses:return []
    rows=db.query(Event).filter(Event.tenant_id==tenant_id,Event.timestamp>=start,Event.timestamp<=newest,or_(*clauses)).order_by(Event.timestamp).limit(1000).all();return [typed for typed in map(typed_from_event,rows) if typed]

def _process_raw_telemetry(db,raw_events,baseline_devices=None,correlate=True,tenant_id="tenant-demo"):
    if not raw_events:return [],[],[]
    current_ids={raw.id for raw in raw_events};stored=[]
    for raw in raw_events:
        existing=db.get(Event,raw.id)
        if existing:stored.append(existing)
        else:event=normalize(raw,tenant_id);db.add(event);stored.append(event)
    db.flush();context=historical_context(db,raw_events,tenant_id);typed={e.id:e for e in context+raw_events};started=time.perf_counter();findings=run_detection(sorted(typed.values(),key=lambda e:e.timestamp),baseline_devices);DETECTION_LATENCY.observe(time.perf_counter()-started)
    # Findings are idempotent first-class records; contextual rules may legitimately annotate history.
    existing_keys={(r.event_id,r.rule_id,r.rule_version,r.flag) for r in db.query(DetectionFindingRecord).filter(DetectionFindingRecord.event_id.in_({f.event_id for f in findings})).all()}
    for item in findings:
        key=(item.event_id,item.rule_id,item.rule_version,item.flag)
        if key not in existing_keys:
            db.add(DetectionFindingRecord(event_id=item.event_id,rule_id=item.rule_id,rule_version=item.rule_version,flag=item.flag,risk_contribution=item.risk_contribution,reason=item.reason,metadata_json=json.dumps(item.metadata),created_at=datetime.now(UTC).replace(tzinfo=None)));existing_keys.add(key)
    db.flush();affected_ids={f.event_id for f in findings};affected=db.query(Event).filter(Event.id.in_(affected_ids)).all() if affected_ids else []
    for event in affected:
        records=db.query(DetectionFindingRecord).filter_by(event_id=event.id).all();event.risk_flags=json.dumps(sorted({r.flag for r in records}));event.risk_score=min(100,sum(r.risk_contribution for r in records));data=json.loads(event.data);data["detection_findings"]=[{"event_id":r.event_id,"rule_id":r.rule_id,"rule_version":r.rule_version,"flag":r.flag,"risk_contribution":r.risk_contribution,"reason":r.reason,"metadata":json.loads(r.metadata_json)} for r in records];event.data=json.dumps(data)
    db.flush();oldest=min(e.timestamp for e in raw_events)-timedelta(minutes=settings.correlation_window_minutes);newest=max(e.timestamp for e in raw_events)+timedelta(minutes=settings.correlation_window_minutes)
    candidates=db.query(Event).filter(Event.tenant_id==tenant_id,Event.timestamp>=oldest,Event.timestamp<=newest,Event.risk_score>0).limit(1000).all();candidate_ids={e.id for e in candidates};records=db.query(DetectionFindingRecord).filter(DetectionFindingRecord.event_id.in_(candidate_ids)).all()
    from ..schemas.telemetry import DetectionFinding
    all_findings=[DetectionFinding(event_id=r.event_id,rule_id=r.rule_id,rule_version=r.rule_version,flag=r.flag,risk_contribution=r.risk_contribution,reason=r.reason,metadata=json.loads(r.metadata_json)) for r in records]
    incidents=create_or_update_incidents(db,candidates,all_findings) if correlate else [];CORRELATION_GROUPS.inc(len(incidents));db.commit();log.info("telemetry_processed",extra={"operation":"telemetry_processed","event_count":len(raw_events),"finding_count":len(findings),"incident_count":len(incidents),"incident_ids":[i.id for i in incidents]})
    return incidents,[f for f in findings if f.event_id in current_ids or f.event_id in affected_ids],stored

def process_raw_telemetry(db,raw_events,baseline_devices=None,correlate=True,tenant_id="tenant-demo"):
    try:
        return _process_raw_telemetry(db,raw_events,baseline_devices,correlate,tenant_id)
    except Exception:
        db.rollback()
        raise
