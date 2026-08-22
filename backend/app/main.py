from contextlib import asynccontextmanager
from datetime import datetime, timedelta, UTC
import json, logging, time, uuid
from fastapi import FastAPI, Depends, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session
from .database import get_db, SessionLocal
from .models import Event, Incident, Activity, AnalystNote, EvidenceBookmark, IncidentRiskHistory, DetectionFindingRecord,ActionApproval,ConnectorExecution
from .schemas.api import DemoRequest, ActionRequest, AskRequest, StatusRequest, NoteRequest, BookmarkRequest, DispositionRequest
from .seed.seed_data import seed_database, BASELINE_DEVICES
from .services.scenario_generator import generate_raw_scenario
from .services.pipeline import process_raw_telemetry
from .services.serializers import serialize_event, serialize_incident
from .services.playbook_engine import PLAYBOOKS, residual_risk, containment_progress
from .services.investigation_ai import investigate
from .logging_config import configure_logging
from .auth import seed_identity,current_principal,require_role,Principal
from .config import settings
from .platform_api import router as platform_router
from .connectors import connector
from .observability import install_observability,ACTIONS,HTTP_LATENCY

@asynccontextmanager
async def lifespan(app):
    db=SessionLocal()
    try: seed_identity(db);seed_database(db)
    finally: db.close()
    yield

app=FastAPI(title="CIRT Lens API",version="2.0",lifespan=lifespan)
app.include_router(platform_router);install_observability(app)
app.add_middleware(CORSMiddleware,allow_origins=["http://localhost:5173","http://127.0.0.1:5173"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
configure_logging();logger=logging.getLogger("cirt_lens")

def utcnow(): return datetime.now(UTC).replace(tzinfo=None)
def problem(status,title,detail,request_id=None): return {"error":{"status":status,"title":title,"detail":detail,"request_id":request_id}}
@app.middleware("http")
async def request_context(request:Request,call_next):
    request_id=request.headers.get("x-request-id") or str(uuid.uuid4()); start=time.perf_counter()
    if settings.auth_required and request.url.path.startswith("/api/") and request.url.path not in {"/api/auth/login","/api/health","/api/ready"}:
        try:current_principal(request,None)
        except HTTPException as exc:return JSONResponse(problem(exc.status_code,"Authentication required",str(exc.detail),request_id),status_code=exc.status_code)
    try: response=await call_next(request)
    except Exception:
        logger.exception("request_failed",extra={"request_id":request_id,"path":request.url.path});raise
    response.headers["x-request-id"]=request_id
    HTTP_LATENCY.labels(request.method,request.url.path,str(response.status_code)).observe(time.perf_counter()-start)
    logger.info("request_complete",extra={"request_id":request_id,"method":request.method,"path":request.url.path,"status":response.status_code,"latency_ms":round((time.perf_counter()-start)*1000,2)})
    return response
@app.exception_handler(HTTPException)
async def http_error(request:Request,exc:HTTPException): return JSONResponse(problem(exc.status_code,"Request failed",str(exc.detail),request.headers.get("x-request-id")),status_code=exc.status_code)
@app.exception_handler(RequestValidationError)
async def validation_error(request:Request,exc:RequestValidationError): return JSONResponse(problem(422,"Validation failed",exc.errors(),request.headers.get("x-request-id")),status_code=422)
@app.exception_handler(Exception)
async def server_error(request:Request,exc:Exception):
    logger.exception("unhandled_request_error",extra={"operation":"unhandled_request_error","path":request.url.path});return JSONResponse(problem(500,"Internal server error","The request could not be completed.",request.headers.get("x-request-id")),status_code=500)

def get_incident(iid,db):
    value=db.get(Incident,iid)
    if not value: raise HTTPException(404,"Incident not found")
    return value
def incident_events(value,db): return db.query(Event).filter(Event.id.in_(json.loads(value.event_ids))).order_by(Event.timestamp).all()

@app.get("/api/health")
def health(): return {"status":"operational","mode":"demo","pipeline":"raw→detect→correlate→score"}
@app.get("/api/ready")
def ready(db:Session=Depends(get_db)):
    db.query(Event).limit(1).all()
    dependencies={"database":"reachable"}
    try:
        from redis import Redis
        Redis.from_url(settings.redis_url).ping();dependencies["redis"]="reachable"
    except Exception:dependencies["redis"]="unavailable"
    if settings.auth_required and dependencies["redis"]!="reachable":raise HTTPException(503,"Required dependency unavailable")
    return {"status":"ready","dependencies":dependencies}

@app.get("/api/dashboard")
def dashboard(db:Session=Depends(get_db)):
    incidents=db.query(Incident).order_by(Incident.created_at.desc()).all(); events=db.query(Event).all(); counts={s:sum(i.severity==s for i in incidents) for s in ["CRITICAL","HIGH","MEDIUM","LOW"]}
    trend=[]
    for h in range(24):
        start=utcnow().replace(minute=0,second=0,microsecond=0)-timedelta(hours=23-h); end=start+timedelta(hours=1); trend.append({"hour":start.strftime("%H:00"),"incidents":sum(start<=i.created_at<end for i in incidents)})
    triage=[]
    for item in incidents:
        first=db.query(Activity).filter(Activity.incident_id==item.id,Activity.action=="STATUS_INVESTIGATING").order_by(Activity.timestamp).first()
        if first: triage.append(max(0,(first.timestamp-item.created_at).total_seconds()))
    seconds=sum(triage)/len(triage) if triage else None
    finding_count=db.query(DetectionFindingRecord).count()
    return {"kpis":{"open_incidents":sum(i.status!="RESOLVED" for i in incidents),"critical_incidents":counts["CRITICAL"],"events_analyzed":len(events),"detection_findings":finding_count,"mean_triage_time":"N/A" if seconds is None else f"{int(seconds//60)}m {int(seconds%60)}s"},"severity":counts,"trend":trend,"sources":{s:sum(e.source==s and e.risk_score>0 for e in events) for s in ["Identity","Endpoint","Network","Cloud"]},"recent":[serialize_incident(i) for i in incidents[:8]]}

@app.get("/api/incidents")
def incidents(status:str="",severity:str="",offset:int=Query(0,ge=0),limit:int=Query(100,ge=1,le=500),db:Session=Depends(get_db)):
    query=db.query(Incident)
    if status: query=query.filter(Incident.status==status.upper())
    if severity: query=query.filter(Incident.severity==severity.upper())
    return [serialize_incident(i) for i in query.order_by(Incident.created_at.desc()).offset(offset).limit(limit)]
@app.get("/api/incidents/{iid}")
def incident(iid:str,db:Session=Depends(get_db)):
    value=get_incident(iid,db); return serialize_incident(value,incident_events(value,db),db)
@app.get("/api/incidents/{iid}/timeline")
def timeline(iid:str,db:Session=Depends(get_db)): return [serialize_event(e) for e in incident_events(get_incident(iid,db),db)]
@app.get("/api/incidents/{iid}/evidence")
def evidence(iid:str,db:Session=Depends(get_db)): return timeline(iid,db)

@app.post("/api/incidents/{iid}/actions")
def action(iid:str,body:ActionRequest,p:Principal=Depends(require_role("RESPONDER")),db:Session=Depends(get_db)):
    value=get_incident(iid,db); actions=json.loads(value.recommended_actions); selected=next((a for a in actions if a["action"].lower()==body.action.lower()),None)
    if not selected: raise HTTPException(400,"Action is not recommended for this incident")
    if selected["status"]=="EXECUTED": raise HTTPException(409,"Action has already been executed")
    high_impact=selected.get("reduction_points",0)>=12
    if high_impact and settings.auth_required:
        approval=db.query(ActionApproval).filter_by(tenant_id=p.tenant_id,incident_id=iid,action=selected["action"],status="APPROVED").first()
        if not approval:raise HTTPException(409,"Approved two-person authorization is required for this high-impact action")
    execution_key=f"{p.tenant_id}:{iid}:{selected['action']}";execution=db.query(ConnectorExecution).filter_by(idempotency_key=execution_key).first()
    if not execution:
        result=connector.execute(selected["action"],value.primary_user or value.primary_host or iid,execution_key,dry_run=True);execution=ConnectorExecution(id=f"CON-{uuid.uuid4().hex[:10].upper()}",tenant_id=p.tenant_id,incident_id=iid,action=selected["action"],connector="fake_identity",idempotency_key=execution_key,provider_request_id=result.provider_request_id,status=result.status,dry_run=True,attempts=1,detail=result.detail,created_at=utcnow());db.add(execution)
    now=utcnow(); selected.update(status="EXECUTED",executed_at=now.isoformat()+"Z",analyst=body.analyst); value.recommended_actions=json.dumps(actions); value.residual_risk_score=residual_risk(value.risk_score,actions); value.updated_at=now
    flags={f.flag for f in db.query(DetectionFindingRecord).filter(DetectionFindingRecord.event_id.in_(json.loads(value.event_ids)))}
    progress=containment_progress(flags,actions)
    if progress["required"] and progress["completed"]==progress["required"]: value.status="CONTAINED"
    elif value.status=="NEW": value.status="INVESTIGATING"
    audit=Activity(timestamp=now,analyst=p.email,action=body.action.upper().replace(" ","_"),incident_id=iid,result="SUCCESS",details=f"Connector {execution.connector}; provider request {execution.provider_request_id}; dry-run={execution.dry_run}; estimated reduction {selected.get('reduction_points',0)}.",tenant_id=p.tenant_id); db.add(audit)
    try:db.flush();db.add(IncidentRiskHistory(incident_id=iid,timestamp=now,original_risk=value.risk_score,residual_risk=value.residual_risk_score,reason=f"Executed {body.action}",activity_id=audit.id));db.commit()
    except Exception:db.rollback();raise
    ACTIONS.labels(selected["action"],"SUCCESS").inc();return {"ok":True,"containment_progress":progress,"connector_execution":{"id":execution.id,"provider_request_id":execution.provider_request_id,"status":execution.status,"dry_run":execution.dry_run},"incident":serialize_incident(value)}

@app.patch("/api/incidents/{iid}")
def update_incident(iid:str,body:StatusRequest,db:Session=Depends(get_db)):
    value=get_incident(iid,db)
    target=body.status.value
    if target=="CONTAINED":raise HTTPException(409,"CONTAINED is derived only after required simulated response objectives are completed")
    allowed={"NEW":{"INVESTIGATING"},"INVESTIGATING":{"RESOLVED"},"CONTAINED":{"RESOLVED"},"RESOLVED":set()}
    if target!=value.status and target not in allowed.get(value.status,set()):raise HTTPException(409,f"Invalid workflow transition: {value.status} to {target}")
    now=utcnow(); value.status=target
    if target=="INVESTIGATING": value.assigned_to="analyst@demo"; value.triaged_at=value.triaged_at or now
    value.updated_at=now; db.add(Activity(timestamp=now,analyst="analyst@demo",action=f"STATUS_{target}",incident_id=iid,result="SUCCESS",details="Incident workflow updated.")); db.commit(); return serialize_incident(value)

@app.post("/api/incidents/{iid}/notes",status_code=201)
def add_note(iid:str,body:NoteRequest,db:Session=Depends(get_db)):
    get_incident(iid,db);now=utcnow();note=AnalystNote(incident_id=iid,analyst=body.analyst,text=body.text,timestamp=now);db.add(note);db.add(Activity(timestamp=now,analyst=body.analyst,action="NOTE_ADDED",incident_id=iid,result="SUCCESS",details="Analyst case note added."));db.commit();db.refresh(note);return {"id":note.id,"timestamp":now.isoformat()+"Z"}
@app.post("/api/incidents/{iid}/bookmarks",status_code=201)
def add_bookmark(iid:str,body:BookmarkRequest,db:Session=Depends(get_db)):
    value=get_incident(iid,db)
    if body.event_id not in json.loads(value.event_ids):raise HTTPException(400,"Event does not belong to this incident")
    if db.query(EvidenceBookmark).filter_by(incident_id=iid,event_id=body.event_id).first():raise HTTPException(409,"Evidence is already bookmarked")
    now=utcnow();bookmark=EvidenceBookmark(incident_id=iid,event_id=body.event_id,analyst=body.analyst,note=body.note,timestamp=now);db.add(bookmark);db.add(Activity(timestamp=now,analyst=body.analyst,action="EVIDENCE_BOOKMARKED",incident_id=iid,result="SUCCESS",details=f"Bookmarked {body.event_id}."));db.commit();db.refresh(bookmark);return {"id":bookmark.id,"event_id":body.event_id}
@app.patch("/api/incidents/{iid}/disposition")
def set_disposition(iid:str,body:DispositionRequest,db:Session=Depends(get_db)):
    value=get_incident(iid,db);value.disposition=body.disposition.value;value.updated_at=utcnow();db.add(Activity(timestamp=value.updated_at,analyst=body.analyst,action=f"DISPOSITION_{body.disposition.value}",incident_id=iid,result="SUCCESS",details="Analyst disposition updated."));db.commit();return serialize_incident(value)

@app.post("/api/incidents/{iid}/ask")
def ask(iid:str,body:AskRequest,db:Session=Depends(get_db)):
    value=get_incident(iid,db); return investigate(value,incident_events(value,db),body.question)

@app.post("/api/demo/generate")
def demo(body:DemoRequest,db:Session=Depends(get_db)):
    if body.scenario not in ["credential","endpoint","exfiltration"]: raise HTTPException(400,"Unknown scenario")
    raw=generate_raw_scenario(body.scenario,db.query(Event).count()+1001); created,_,_=process_raw_telemetry(db,raw,BASELINE_DEVICES)
    if not created: raise HTTPException(422,"Generated telemetry did not pass correlation threshold")
    generated_ids={event.id for event in raw}
    selected=max(created,key=lambda item:len(generated_ids&set(json.loads(item.event_ids))))
    return serialize_incident(selected,incident_events(selected,db),db)

@app.get("/api/events")
def events(q:str=Query("",max_length=100),source:str=Query("",max_length=30),flag:str=Query("",max_length=80),start:datetime|None=None,end:datetime|None=None,offset:int=Query(0,ge=0),limit:int=Query(500,ge=1,le=1000),db:Session=Depends(get_db)):
    query=db.query(Event)
    if source: query=query.filter(Event.source==source)
    if flag: query=query.filter(Event.risk_flags.contains(flag))
    if start:query=query.filter(Event.timestamp>=start)
    if end:query=query.filter(Event.timestamp<=end)
    if q: query=query.filter(or_(Event.user.contains(q),Event.host.contains(q),Event.source_ip.contains(q),Event.activity.contains(q),Event.risk_flags.contains(q)))
    return [serialize_event(e) for e in query.order_by(Event.timestamp.desc()).offset(offset).limit(limit)]
@app.get("/api/hunt")
def hunt(query:str=Query("",max_length=150),db:Session=Depends(get_db)):
    field,value=(query.split(":",1)+[""])[:2] if ":" in query else ("all",query); column={"user":Event.user,"host":Event.host,"ip":Event.source_ip,"flag":Event.risk_flags}.get(field); statement=db.query(Event)
    if value: statement=statement.filter(column.contains(value) if column is not None else or_(Event.user.contains(value),Event.host.contains(value),Event.source_ip.contains(value),Event.activity.contains(value),Event.risk_flags.contains(value)))
    return [serialize_event(e) for e in statement.order_by(Event.timestamp.desc()).limit(300)]

@app.get("/api/search")
def search(q:str=Query(min_length=2,max_length=100),db:Session=Depends(get_db)):
    found=db.query(Incident).filter(or_(Incident.id.contains(q),Incident.title.contains(q),Incident.primary_user.contains(q),Incident.primary_host.contains(q))).limit(5).all(); ev=db.query(Event).filter(or_(Event.id.contains(q),Event.user.contains(q),Event.host.contains(q),Event.source_ip.contains(q),Event.activity.contains(q))).order_by(Event.timestamp.desc()).limit(8).all()
    def values(attribute): return sorted({getattr(e,attribute) for e in db.query(Event).filter(getattr(Event,attribute).contains(q)).limit(20) if getattr(e,attribute)})[:5]
    return {"incidents":[serialize_incident(i) for i in found],"users":values("user"),"hosts":values("host"),"ips":values("source_ip"),"events":[serialize_event(e) for e in ev]}

@app.get("/api/playbooks")
def playbooks(): return [{**p,"actions":list(p["actions"])} for p in PLAYBOOKS]
@app.get("/api/activity")
def activity(db:Session=Depends(get_db)): return [{"id":a.id,"timestamp":a.timestamp.isoformat()+"Z","analyst":a.analyst,"action":a.action,"incident_id":a.incident_id,"result":a.result,"details":a.details} for a in db.query(Activity).order_by(Activity.timestamp.desc()).all()]

@app.get("/api/incidents/{iid}/report",response_class=PlainTextResponse)
def report(iid:str,db:Session=Depends(get_db)):
    value=get_incident(iid,db); event_list=incident_events(value,db); ids=json.loads(value.event_ids);techniques=json.loads(value.techniques); actions=json.loads(value.recommended_actions); audit=db.query(Activity).filter(Activity.incident_id==iid).order_by(Activity.timestamp).all();findings=db.query(DetectionFindingRecord).filter(DetectionFindingRecord.event_id.in_(ids)).all();notes=db.query(AnalystNote).filter_by(incident_id=iid).order_by(AnalystNote.timestamp).all();bookmarks=db.query(EvidenceBookmark).filter_by(incident_id=iid).order_by(EvidenceBookmark.timestamp).all();history=db.query(IncidentRiskHistory).filter_by(incident_id=iid).order_by(IncidentRiskHistory.timestamp).all();progress=containment_progress({f.flag for f in findings},actions)
    lines=["# CIRT Lens Incident Report","","> Generated from synthetic demonstration telemetry.","> CIRT Lens is a portfolio demonstration and does not perform real containment.","> Analyst notes are untrusted user-authored text reproduced verbatim.","",f"**Incident ID:** {value.id}  ",f"**Incident Fingerprint:** {value.incident_fingerprint or 'legacy/unavailable'}  ",f"**Incident Type:** {value.incident_type}  ",f"**Severity:** {value.severity}  ",f"**Status:** {value.status}  ",f"**Disposition:** {value.disposition}  ",f"**Original Risk:** {value.risk_score}/100  ",f"**Residual Risk:** {value.residual_risk_score}/100  ",f"**Evidence Confidence:** {value.confidence_score}/100","","## Executive Summary","",value.description,"","## Root Cause Hypothesis","",value.root_cause,"","## Risk Breakdown","",*['- '+k+': '+str(v) for k,v in json.loads(value.score_breakdown).items()],"","## Evidence Confidence Breakdown","",*['- '+k+': '+str(v) for k,v in json.loads(value.confidence_breakdown or '{}').items()],"","## Timeline","",*[f"- {e.timestamp.isoformat()}Z — **{e.id}** — {e.activity}" for e in event_list],"","## Evidence","",*[f"- {e.id}: {e.source}; flags: {', '.join(json.loads(e.risk_flags)) or 'none'}; risk: {e.risk_score}" for e in event_list],"","## Detection Findings","",*[f"- {f.rule_id} v{f.rule_version} — {f.flag} on {f.event_id}: {f.reason}" for f in findings],"","## MITRE ATT&CK","",*[f"- {t['id']} {t['name']}: {t['reason']} Evidence: {', '.join(t['evidence_ids'])}" for t in techniques],"","## Case Notes","",*([f"- {n.timestamp.isoformat()}Z {n.analyst}: {n.text}" for n in notes] or ["- None"]),"","## Bookmarked Evidence","",*([f"- {b.event_id}: {b.note or 'No note'}" for b in bookmarks] or ["- None"]),"","## Containment Objectives","",*[f"- {o['id']}: {'complete' if o['complete'] else 'pending'}" for o in progress['objectives']],"","## Executed and Recommended Actions","",*[f"- {a['action']} — {a['status']}" for a in actions],"","## Risk History","",*[f"- {h.timestamp.isoformat()}Z — {h.original_risk} → {h.residual_risk}: {h.reason}" for h in history],"","## Audit Summary","",*[f"- {a.timestamp.isoformat()}Z {a.analyst} {a.action} {a.result}" for a in audit],"","## Recommended Follow-Up","","Validate ownership, review adjacent telemetry, confirm scope, and preserve evidence.","",f"Generated: {utcnow().isoformat()}Z"]
    return "\n".join(lines)
