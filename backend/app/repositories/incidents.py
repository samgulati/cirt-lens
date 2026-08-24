import json

from sqlalchemy.orm import Session

from ..errors import DomainError
from ..models import Event, Incident


class IncidentRepository:
    """All incident access requires an explicit tenant boundary."""

    def __init__(self, db: Session, tenant_id: str):
        self.db = db
        self.tenant_id = tenant_id

    def get(self, incident_id: str) -> Incident:
        incident = (
            self.db.query(Incident).filter_by(id=incident_id, tenant_id=self.tenant_id).first()
        )
        if not incident:
            raise DomainError(404, "Incident not found")
        return incident

    def events(self, incident: Incident) -> list[Event]:
        event_ids = json.loads(incident.event_ids)
        return (
            self.db.query(Event)
            .filter(Event.tenant_id == self.tenant_id, Event.id.in_(event_ids))
            .order_by(Event.timestamp)
            .all()
        )
