from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class Event(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    source: Mapped[str] = mapped_column(String, index=True)
    user: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    host: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    activity: Mapped[str] = mapped_column(String)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_flags: Mapped[str] = mapped_column(Text, default="[]")
    data: Mapped[str] = mapped_column(Text, default="{}")
    schema_version: Mapped[str] = mapped_column(String, default="1.0")
    tenant_id: Mapped[str] = mapped_column(String, default="tenant-demo", index=True)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    title: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    updated_at: Mapped[datetime] = mapped_column(DateTime)
    severity: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="NEW")
    risk_score: Mapped[int] = mapped_column(Integer)
    confidence_score: Mapped[int] = mapped_column(Integer)
    primary_user: Mapped[str | None] = mapped_column(String, nullable=True)
    primary_host: Mapped[str | None] = mapped_column(String, nullable=True)
    source_ips: Mapped[str] = mapped_column(Text, default="[]")
    affected_assets: Mapped[str] = mapped_column(Text, default="[]")
    event_ids: Mapped[str] = mapped_column(Text, default="[]")
    techniques: Mapped[str] = mapped_column(Text, default="[]")
    recommended_actions: Mapped[str] = mapped_column(Text, default="[]")
    root_cause: Mapped[str] = mapped_column(Text)
    score_breakdown: Mapped[str] = mapped_column(Text, default="{}")
    assigned_to: Mapped[str | None] = mapped_column(String, nullable=True)
    incident_type: Mapped[str] = mapped_column(String, default="Security Incident")
    residual_risk_score: Mapped[int] = mapped_column(Integer, default=0)
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    incident_fingerprint: Mapped[str | None] = mapped_column(
        String, nullable=True, unique=True, index=True
    )
    confidence_breakdown: Mapped[str] = mapped_column(Text, default="{}")
    disposition: Mapped[str] = mapped_column(String, default="UNSET")
    tenant_id: Mapped[str] = mapped_column(String, default="tenant-demo", index=True)


class Activity(Base):
    __tablename__ = "activity"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    analyst: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String)
    incident_id: Mapped[str] = mapped_column(String)
    result: Mapped[str] = mapped_column(String)
    details: Mapped[str] = mapped_column(Text, default="")
    tenant_id: Mapped[str] = mapped_column(String, default="tenant-demo", index=True)


class DetectionFindingRecord(Base):
    __tablename__ = "detection_findings"
    __table_args__ = (
        UniqueConstraint(
            "event_id", "rule_id", "rule_version", "flag", name="uq_finding_event_rule_version_flag"
        ),
        Index("ix_findings_rule_flag", "rule_id", "flag"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String, index=True)
    rule_id: Mapped[str] = mapped_column(String, index=True)
    rule_version: Mapped[str] = mapped_column(String)
    flag: Mapped[str] = mapped_column(String, index=True)
    risk_contribution: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime)


class AnalystNote(Base):
    __tablename__ = "analyst_notes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String, index=True)
    analyst: Mapped[str] = mapped_column(String)
    text: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime)


class EvidenceBookmark(Base):
    __tablename__ = "evidence_bookmarks"
    __table_args__ = (
        UniqueConstraint("incident_id", "event_id", name="uq_bookmark_incident_event"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String, index=True)
    event_id: Mapped[str] = mapped_column(String, index=True)
    analyst: Mapped[str] = mapped_column(String)
    note: Mapped[str] = mapped_column(Text, default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime)


class IncidentRiskHistory(Base):
    __tablename__ = "incident_risk_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    original_risk: Mapped[int] = mapped_column(Integer)
    residual_risk: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(String)
    activity_id: Mapped[int | None] = mapped_column(Integer, nullable=True)


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)


class UserAccount(Base):
    __tablename__ = "user_accounts"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),)
    id: Mapped[str] = mapped_column(String, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String, index=True)
    email: Mapped[str] = mapped_column(String, index=True)
    display_name: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String, index=True)
    password_hash: Mapped[str] = mapped_column(String)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)


class ActionApproval(Base):
    __tablename__ = "action_approvals"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "incident_id", "action", "status", name="uq_open_action_approval"
        ),
        Index("ix_approval_tenant_status", "tenant_id", "status"),
    )
    id: Mapped[str] = mapped_column(String, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String, index=True)
    incident_id: Mapped[str] = mapped_column(String, index=True)
    action: Mapped[str] = mapped_column(String)
    requested_by: Mapped[str] = mapped_column(String)
    approved_by: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, default="PENDING")
    created_at: Mapped[datetime] = mapped_column(DateTime)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_job_tenant_idempotency"),
        Index("ix_job_tenant_status", "tenant_id", "status"),
    )
    id: Mapped[str] = mapped_column(String, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String, index=True)
    idempotency_key: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="QUEUED")
    event_count: Mapped[int] = mapped_column(Integer)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    stream_id: Mapped[str | None] = mapped_column(String, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    updated_at: Mapped[datetime] = mapped_column(DateTime)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (
        UniqueConstraint("tenant_id", "rule_id", "version", name="uq_rule_version"),
        Index("ix_rule_tenant_status", "tenant_id", "status"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String, index=True)
    rule_id: Mapped[str] = mapped_column(String, index=True)
    version: Mapped[str] = mapped_column(String)
    name: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="DRAFT")
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    parameters_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime)
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ConnectorExecution(Base):
    __tablename__ = "connector_executions"
    __table_args__ = (UniqueConstraint("idempotency_key", name="uq_connector_idempotency"),)
    id: Mapped[str] = mapped_column(String, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String, index=True)
    incident_id: Mapped[str] = mapped_column(String, index=True)
    action: Mapped[str] = mapped_column(String)
    connector: Mapped[str] = mapped_column(String)
    idempotency_key: Mapped[str] = mapped_column(String)
    provider_request_id: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    attempts: Mapped[int] = mapped_column(Integer, default=1)
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime)
