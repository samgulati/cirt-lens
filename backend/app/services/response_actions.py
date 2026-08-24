import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from ..auth import Principal
from ..config import settings
from ..connectors import ConnectorError, IdentityConnector
from ..errors import DomainError
from ..models import (
    ActionApproval,
    Activity,
    ConnectorExecution,
    DetectionFindingRecord,
    IncidentRiskHistory,
)
from ..observability import ACTIONS, APPROVALS, CONNECTOR_FAILURES
from ..repositories.incidents import IncidentRepository
from .playbook_engine import containment_progress, residual_risk
from .serializers import serialize_incident


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class ResponseActionService:
    """Executes an approved response action inside one explicit transaction."""

    def __init__(self, db: Session, connector: IdentityConnector):
        self.db = db
        self.connector = connector

    def execute(self, incident_id: str, requested_action: str, principal: Principal) -> dict:
        repository = IncidentRepository(self.db, principal.tenant_id)
        incident = repository.get(incident_id)
        actions = json.loads(incident.recommended_actions)
        selected = next(
            (item for item in actions if item["action"].lower() == requested_action.lower()), None
        )
        if not selected:
            raise DomainError(400, "Action is not recommended for this incident")
        if selected["status"] == "EXECUTED":
            raise DomainError(409, "Action has already been executed")
        approval = self._require_approval(incident_id, selected, principal)
        execution = self._connector_execution(incident, selected, principal)
        now = utcnow()
        selected.update(
            status="EXECUTED", executed_at=now.isoformat() + "Z", analyst=principal.email
        )
        incident.recommended_actions = json.dumps(actions)
        incident.residual_risk_score = residual_risk(incident.risk_score, actions)
        incident.updated_at = now
        progress = containment_progress(self._finding_flags(incident.event_ids), actions)
        if progress["required"] and progress["completed"] == progress["required"]:
            incident.status = "CONTAINED"
        elif incident.status == "NEW":
            incident.status = "INVESTIGATING"
        audit = self._audit(incident_id, requested_action, principal, execution, selected, now)
        if approval is not None:
            # An authorization is a single-use capability. Consuming it in the same
            # transaction as the action prevents approval replay after partial failures.
            approval.status = "CONSUMED"
            APPROVALS.labels("CONSUMED").inc()
        try:
            self.db.flush()
            self.db.add(
                IncidentRiskHistory(
                    incident_id=incident_id,
                    timestamp=now,
                    original_risk=incident.risk_score,
                    residual_risk=incident.residual_risk_score,
                    reason=f"Executed {requested_action}",
                    activity_id=audit.id,
                )
            )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        ACTIONS.labels(selected["action"], "SUCCESS").inc()
        return {
            "ok": True,
            "containment_progress": progress,
            "connector_execution": {
                "id": execution.id,
                "provider_request_id": execution.provider_request_id,
                "status": execution.status,
                "dry_run": execution.dry_run,
            },
            "incident": serialize_incident(incident),
        }

    def _require_approval(
        self, incident_id: str, selected: dict, principal: Principal
    ) -> ActionApproval | None:
        if selected.get("reduction_points", 0) < 12 or not settings.auth_required:
            return None
        approval = (
            self.db.query(ActionApproval)
            .filter_by(
                tenant_id=principal.tenant_id,
                incident_id=incident_id,
                action=selected["action"],
                status="APPROVED",
            )
            .first()
        )
        if not approval:
            raise DomainError(
                409, "Approved two-person authorization is required for this high-impact action"
            )
        if not approval.decided_at or approval.decided_at < utcnow() - timedelta(
            minutes=settings.approval_ttl_minutes
        ):
            approval.status = "EXPIRED"
            self.db.commit()
            raise DomainError(409, "The approval has expired; request a new authorization")
        return approval

    def _connector_execution(self, incident, selected: dict, principal: Principal):
        key = f"{principal.tenant_id}:{incident.id}:{selected['action']}"
        execution = (
            self.db.query(ConnectorExecution)
            .filter_by(tenant_id=principal.tenant_id, idempotency_key=key)
            .first()
        )
        if execution:
            return execution
        dry_run = not settings.auth0_connector_live
        try:
            result = self.connector.execute(
                selected["action"],
                incident.primary_user or incident.primary_host or incident.id,
                key,
                dry_run=dry_run,
            )
        except ConnectorError as exc:
            CONNECTOR_FAILURES.labels(
                self.connector.name, exc.code, str(exc.retryable).lower()
            ).inc()
            raise DomainError(502, str(exc)) from exc
        execution = ConnectorExecution(
            id=f"CON-{uuid.uuid4().hex[:10].upper()}",
            tenant_id=principal.tenant_id,
            incident_id=incident.id,
            action=selected["action"],
            connector=self.connector.name,
            idempotency_key=key,
            provider_request_id=result.provider_request_id,
            status=result.status,
            dry_run=dry_run,
            attempts=1,
            detail=result.detail,
            created_at=utcnow(),
        )
        self.db.add(execution)
        return execution

    def _finding_flags(self, event_ids_json: str) -> set[str]:
        return {
            finding.flag
            for finding in self.db.query(DetectionFindingRecord).filter(
                DetectionFindingRecord.event_id.in_(json.loads(event_ids_json))
            )
        }

    def _audit(self, incident_id, action, principal, execution, selected, timestamp):
        audit = Activity(
            timestamp=timestamp,
            analyst=principal.email,
            action=action.upper().replace(" ", "_"),
            incident_id=incident_id,
            result="SUCCESS",
            details=(
                f"Connector {execution.connector}; provider request "
                f"{execution.provider_request_id}; dry-run={execution.dry_run}; "
                f"estimated reduction {selected.get('reduction_points', 0)}."
            ),
            tenant_id=principal.tenant_id,
        )
        self.db.add(audit)
        return audit
