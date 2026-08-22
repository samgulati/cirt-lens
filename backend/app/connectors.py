"""Replaceable response connector contract and deterministic fake provider."""
from dataclasses import dataclass
import uuid
@dataclass
class ConnectorResult:status:str;provider_request_id:str;detail:str
class IdentityConnector:
    def execute(self,action,subject,idempotency_key,dry_run=True):raise NotImplementedError
    def status(self,provider_request_id):raise NotImplementedError
class FakeIdentityConnector(IdentityConnector):
    def execute(self,action,subject,idempotency_key,dry_run=True):return ConnectorResult("SUCCEEDED",f"FAKE-{uuid.uuid5(uuid.NAMESPACE_URL,idempotency_key).hex[:12].upper()}",f"{'Dry-run' if dry_run else 'Simulated'} {action} for {subject}; no external system modified.")
    def status(self,provider_request_id):return ConnectorResult("SUCCEEDED",provider_request_id,"Deterministic fake provider completed the request.")
connector=FakeIdentityConnector()
