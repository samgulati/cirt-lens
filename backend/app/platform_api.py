import json
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field, TypeAdapter
from redis import Redis
from sqlalchemy.orm import Session

from .auth import Principal, current_principal, issue_token, require_permission, verify_password
from .config import settings
from .connectors import connector
from .database import get_db
from .models import (
    ActionApproval,
    Activity,
    ConnectorExecution,
    DetectionRule,
    Event,
    Incident,
    IngestionJob,
    UserAccount,
)
from .observability import APPROVAL_AGE, APPROVALS, DLQ_DEPTH, INGESTION, QUEUE_DEPTH
from .schemas.telemetry import TelemetryInput
from .services.detection_engine import RULES, run_detection
from .services.pipeline import typed_from_event

router = APIRouter(prefix="/api")


def now():
    return datetime.now(UTC).replace(tzinfo=None)


class Login(BaseModel):
    email: str
    password: str


class ApprovalRequest(BaseModel):
    action: str = Field(min_length=2, max_length=100)


class RuleCreate(BaseModel):
    rule_id: str
    version: str
    name: str
    description: str
    owner: str = "detection-engineering"
    severity: str = "MEDIUM"
    parameters: dict = {}


class RuleStatus(BaseModel):
    status: str


class IngestRequest(BaseModel):
    events: list[dict] = Field(min_length=1, max_length=500)


@router.post("/auth/login")
def login(body: Login, db: Session = Depends(get_db)):
    user = db.query(UserAccount).filter_by(email=body.email, active=True).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    return {
        "access_token": issue_token(user),
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "role": user.role,
            "tenant_id": user.tenant_id,
        },
    }


@router.get("/auth/me")
def me(p: Principal = Depends(current_principal)):
    return p.__dict__


@router.post("/incidents/{incident_id}/approvals", status_code=201)
def request_approval(
    incident_id: str,
    body: ApprovalRequest,
    p: Principal = Depends(require_permission("actions:request")),
    db: Session = Depends(get_db),
):
    incident = db.query(Incident).filter_by(id=incident_id, tenant_id=p.tenant_id).first()
    if not incident:
        raise HTTPException(404, "Incident not found")
    existing = (
        db.query(ActionApproval)
        .filter_by(
            tenant_id=p.tenant_id, incident_id=incident_id, action=body.action, status="PENDING"
        )
        .first()
    )
    if existing:
        return {"id": existing.id, "status": existing.status}
    approval = ActionApproval(
        id=f"APR-{uuid.uuid4().hex[:10].upper()}",
        tenant_id=p.tenant_id,
        incident_id=incident_id,
        action=body.action,
        requested_by=p.user_id,
        status="PENDING",
        created_at=now(),
    )
    db.add(approval)
    db.add(
        Activity(
            timestamp=now(),
            analyst=p.email,
            action="APPROVAL_REQUESTED",
            incident_id=incident_id,
            result="PENDING",
            details=body.action,
            tenant_id=p.tenant_id,
        )
    )
    db.commit()
    APPROVALS.labels("REQUESTED").inc()
    return {"id": approval.id, "status": approval.status}


@router.post("/approvals/{approval_id}/approve")
def approve(
    approval_id: str,
    p: Principal = Depends(require_permission("actions:approve")),
    db: Session = Depends(get_db),
):
    item = db.query(ActionApproval).filter_by(id=approval_id, tenant_id=p.tenant_id).first()
    if not item:
        raise HTTPException(404, "Approval not found")
    if item.requested_by == p.user_id:
        raise HTTPException(409, "Two-person control requires a different approver")
    if item.status != "PENDING":
        raise HTTPException(409, "Approval is already decided")
    item.status = "APPROVED"
    item.approved_by = p.user_id
    item.decided_at = now()
    db.add(
        Activity(
            timestamp=now(),
            analyst=p.email,
            action="ACTION_APPROVED",
            incident_id=item.incident_id,
            result="SUCCESS",
            details=item.action,
            tenant_id=p.tenant_id,
        )
    )
    db.commit()
    APPROVALS.labels("APPROVED").inc()
    APPROVAL_AGE.observe(max(0, (now() - item.created_at).total_seconds()))
    return {"id": item.id, "status": item.status}


@router.get("/approvals")
def approvals(
    p: Principal = Depends(require_permission("actions:approve")), db: Session = Depends(get_db)
):
    return [
        {
            "id": x.id,
            "incident_id": x.incident_id,
            "action": x.action,
            "requested_by": x.requested_by,
            "approved_by": x.approved_by,
            "status": x.status,
            "created_at": x.created_at.isoformat() + "Z",
        }
        for x in db.query(ActionApproval)
        .filter_by(tenant_id=p.tenant_id)
        .order_by(ActionApproval.created_at.desc())
        .limit(100)
    ]


@router.post("/telemetry/ingest", status_code=202)
def ingest(
    body: IngestRequest,
    idempotency_key: str = Header(min_length=8, max_length=100),
    p: Principal = Depends(require_permission("telemetry:ingest")),
    db: Session = Depends(get_db),
):
    existing = (
        db.query(IngestionJob)
        .filter_by(tenant_id=p.tenant_id, idempotency_key=idempotency_key)
        .first()
    )
    if existing:
        INGESTION.labels("DEDUPLICATED").inc()
        return {"job_id": existing.id, "status": existing.status, "deduplicated": True}
    adapter = TypeAdapter(list[TelemetryInput])
    validated = adapter.validate_python(body.events)
    job = IngestionJob(
        id=f"JOB-{uuid.uuid4().hex[:12].upper()}",
        tenant_id=p.tenant_id,
        idempotency_key=idempotency_key,
        status="QUEUED",
        event_count=len(validated),
        attempts=0,
        created_at=now(),
        updated_at=now(),
    )
    db.add(job)
    db.commit()
    try:
        stream_id = Redis.from_url(settings.redis_url, decode_responses=True).xadd(
            settings.telemetry_stream,
            {
                "job_id": job.id,
                "tenant_id": p.tenant_id,
                "events": json.dumps([x.model_dump(mode="json") for x in validated]),
            },
        )
        job.stream_id = stream_id
        db.commit()
        INGESTION.labels("QUEUED").inc()
    except Exception as exc:
        job.status = "QUEUE_UNAVAILABLE"
        job.error = str(exc)[:500]
        job.updated_at = now()
        db.commit()
        INGESTION.labels("QUEUE_UNAVAILABLE").inc()
        raise HTTPException(503, "Ingestion queue unavailable") from exc
    return {
        "job_id": job.id,
        "status": job.status,
        "stream_id": job.stream_id,
        "deduplicated": False,
    }


@router.get("/telemetry/jobs/{job_id}")
def job(
    job_id: str,
    p: Principal = Depends(require_permission("telemetry:read")),
    db: Session = Depends(get_db),
):
    value = db.query(IngestionJob).filter_by(id=job_id, tenant_id=p.tenant_id).first()
    if not value:
        raise HTTPException(404, "Job not found")
    return {
        "id": value.id,
        "status": value.status,
        "event_count": value.event_count,
        "attempts": value.attempts,
        "error": value.error,
        "stream_id": value.stream_id,
        "created_at": value.created_at.isoformat() + "Z",
        "updated_at": value.updated_at.isoformat() + "Z",
    }


@router.get("/telemetry/jobs")
def jobs(
    status: str | None = None,
    limit: int = 100,
    p: Principal = Depends(require_permission("telemetry:read")),
    db: Session = Depends(get_db),
):
    query = db.query(IngestionJob).filter_by(tenant_id=p.tenant_id)
    if status:
        query = query.filter(IngestionJob.status == status.upper())
    return [
        {
            "id": value.id,
            "status": value.status,
            "event_count": value.event_count,
            "attempts": value.attempts,
            "error": value.error,
            "stream_id": value.stream_id,
            "created_at": value.created_at.isoformat() + "Z",
            "updated_at": value.updated_at.isoformat() + "Z",
        }
        for value in query.order_by(IngestionJob.created_at.desc()).limit(max(1, min(limit, 500)))
    ]


@router.get("/operations/queue")
def queue_status(p: Principal = Depends(require_permission("audit:read"))):
    """Return dependency-backed queue evidence without exposing event payloads."""
    try:
        redis = Redis.from_url(settings.redis_url, decode_responses=True)
        stream_depth = redis.xlen(settings.telemetry_stream)
        dlq_depth = redis.xlen(settings.telemetry_dlq)
        QUEUE_DEPTH.set(stream_depth)
        DLQ_DEPTH.set(dlq_depth)
        return {
            "available": True,
            "stream_depth": stream_depth,
            "dlq_depth": dlq_depth,
            "tenant_id": p.tenant_id,
        }
    except Exception:
        return {
            "available": False,
            "stream_depth": None,
            "dlq_depth": None,
            "tenant_id": p.tenant_id,
        }


def bootstrap_rules(db, tenant_id: str):
    for rule_id, (name, version, description, risk, category) in RULES.items():
        if (
            not db.query(DetectionRule)
            .filter_by(tenant_id=tenant_id, rule_id=rule_id, version=version)
            .first()
        ):
            db.add(
                DetectionRule(
                    tenant_id=tenant_id,
                    rule_id=rule_id,
                    version=version,
                    name=name,
                    description=description,
                    owner="detection-engineering",
                    severity="HIGH" if risk >= 30 else "MEDIUM",
                    status="ACTIVE",
                    enabled=True,
                    parameters_json=json.dumps({"risk_contribution": risk, "category": category}),
                    created_at=now(),
                    promoted_at=now(),
                )
            )
    db.commit()


@router.get("/rules")
def rules(p: Principal = Depends(require_permission("rules:read")), db: Session = Depends(get_db)):
    bootstrap_rules(db, p.tenant_id)
    return [
        {
            "id": x.id,
            "rule_id": x.rule_id,
            "version": x.version,
            "name": x.name,
            "description": x.description,
            "owner": x.owner,
            "severity": x.severity,
            "status": x.status,
            "enabled": x.enabled,
            "parameters": json.loads(x.parameters_json),
        }
        for x in db.query(DetectionRule)
        .filter_by(tenant_id=p.tenant_id)
        .order_by(DetectionRule.rule_id, DetectionRule.version)
    ]


@router.post("/rules", status_code=201)
def create_rule(
    body: RuleCreate,
    p: Principal = Depends(require_permission("rules:manage")),
    db: Session = Depends(get_db),
):
    if (
        db.query(DetectionRule)
        .filter_by(tenant_id=p.tenant_id, rule_id=body.rule_id, version=body.version)
        .first()
    ):
        raise HTTPException(409, "Rule version already exists")
    value = DetectionRule(
        tenant_id=p.tenant_id,
        rule_id=body.rule_id,
        version=body.version,
        name=body.name,
        description=body.description,
        owner=body.owner,
        severity=body.severity,
        status="DRAFT",
        enabled=False,
        parameters_json=json.dumps(body.parameters),
        created_at=now(),
    )
    db.add(value)
    db.commit()
    db.refresh(value)
    return {"id": value.id, "status": value.status}


@router.patch("/rules/{rule_id}/{version}/status")
def promote_rule(
    rule_id: str,
    version: str,
    body: RuleStatus,
    p: Principal = Depends(require_permission("rules:manage")),
    db: Session = Depends(get_db),
):
    value = (
        db.query(DetectionRule)
        .filter_by(tenant_id=p.tenant_id, rule_id=rule_id, version=version)
        .first()
    )
    if not value:
        raise HTTPException(404, "Rule not found")
    transitions = {
        "DRAFT": {"TESTING"},
        "TESTING": {"ACTIVE", "DRAFT"},
        "ACTIVE": {"RETIRED"},
        "RETIRED": set(),
    }
    target = body.status.upper()
    if target not in transitions[value.status]:
        raise HTTPException(409, f"Invalid transition {value.status} to {target}")
    if target == "ACTIVE":
        for old in db.query(DetectionRule).filter_by(
            tenant_id=p.tenant_id, rule_id=rule_id, status="ACTIVE"
        ):
            old.status = "RETIRED"
            old.enabled = False
        value.enabled = True
        value.promoted_at = now()
    value.status = target
    db.commit()
    return {"rule_id": rule_id, "version": version, "status": target, "enabled": value.enabled}


@router.post("/rules/replay")
def replay(
    event_ids: list[str],
    p: Principal = Depends(require_permission("rules:manage")),
    db: Session = Depends(get_db),
):
    rows = db.query(Event).filter(Event.id.in_(event_ids), Event.tenant_id == p.tenant_id).all()
    typed = [x for x in map(typed_from_event, rows) if x]
    findings = run_detection(typed)
    return {
        "mode": "NON_MUTATING_REPLAY",
        "events_evaluated": len(typed),
        "findings": [x.model_dump() for x in findings],
        "database_writes": 0,
    }


@router.get("/events/cursor")
def cursor_events(
    cursor: str | None = None,
    limit: int = 100,
    p: Principal = Depends(require_permission("telemetry:read")),
    db: Session = Depends(get_db),
):
    limit = max(1, min(limit, 500))
    query = db.query(Event).filter(Event.tenant_id == p.tenant_id)
    if cursor:
        query = query.filter(Event.id > cursor)
    rows = query.order_by(Event.id).limit(limit + 1).all()
    page = rows[:limit]
    return {
        "items": [
            {
                "id": x.id,
                "timestamp": x.timestamp.isoformat() + "Z",
                "source": x.source,
                "activity": x.activity,
                "risk_score": x.risk_score,
            }
            for x in page
        ],
        "next_cursor": page[-1].id if len(rows) > limit else None,
    }


@router.get("/connector-executions")
def connector_executions(
    p: Principal = Depends(require_permission("audit:read")), db: Session = Depends(get_db)
):
    rows = (
        db.query(ConnectorExecution)
        .filter_by(tenant_id=p.tenant_id)
        .order_by(ConnectorExecution.created_at.desc())
        .limit(100)
        .all()
    )
    return [
        {
            "id": row.id,
            "incident_id": row.incident_id,
            "action": row.action,
            "connector": row.connector,
            "provider_request_id": row.provider_request_id,
            "status": row.status,
            "dry_run": row.dry_run,
            "attempts": row.attempts,
            "detail": row.detail,
            "created_at": row.created_at.isoformat() + "Z",
        }
        for row in rows
    ]


@router.post("/connector-executions/{execution_id}/reconcile")
def reconcile_connector_execution(
    execution_id: str,
    p: Principal = Depends(require_permission("actions:execute")),
    db: Session = Depends(get_db),
):
    execution = (
        db.query(ConnectorExecution).filter_by(id=execution_id, tenant_id=p.tenant_id).first()
    )
    if not execution:
        raise HTTPException(404, "Connector execution not found")
    result = connector.status(execution.provider_request_id or execution.id)
    execution.status = result.status
    execution.detail = result.detail
    db.commit()
    return {"id": execution.id, "status": execution.status, "detail": execution.detail}
