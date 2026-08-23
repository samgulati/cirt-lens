"""Replaceable response connectors with an allowlisted Auth0 sandbox implementation."""
from dataclasses import dataclass
import time,uuid
from urllib.parse import quote
import httpx
from .config import settings

@dataclass(frozen=True)
class ConnectorResult:status:str;provider_request_id:str;detail:str
class ConnectorError(RuntimeError):pass
class IdentityConnector:
    name="identity"
    def execute(self,action,subject,idempotency_key,dry_run=True):raise NotImplementedError
    def status(self,provider_request_id):raise NotImplementedError
class FakeIdentityConnector(IdentityConnector):
    name="fake_identity"
    def execute(self,action,subject,idempotency_key,dry_run=True):return ConnectorResult("SUCCEEDED",f"FAKE-{uuid.uuid5(uuid.NAMESPACE_URL,idempotency_key).hex[:12].upper()}",f"{'Dry-run' if dry_run else 'Simulated'} {action} for {subject}; no external system modified.")
    def status(self,provider_request_id):return ConnectorResult("SUCCEEDED",provider_request_id,"Deterministic fake provider completed the request.")

class Auth0IdentityConnector(IdentityConnector):
    name="auth0_management";supported_actions={"Disable account"}
    def __init__(self,domain,client_id,client_secret,allowed_users,target_override="",transport=None):
        self.domain=domain.removeprefix("https://").rstrip("/");self.client_id=client_id;self.client_secret=client_secret
        self.allowed_users={value.strip().lower() for value in allowed_users.split(",") if value.strip()};self.target_override=target_override.strip().lower()
        self.client=httpx.Client(timeout=8,transport=transport);self._token="";self._token_expires_at=0.0
    def _target(self,subject):
        target=self.target_override or str(subject).strip().lower()
        if not target or target not in self.allowed_users:raise ConnectorError("Auth0 target is not explicitly allowlisted")
        return target
    def _request(self,method,url,**kwargs):
        response=None
        for attempt in range(3):
            try:response=self.client.request(method,url,**kwargs)
            except httpx.RequestError as exc:
                if attempt==2:raise ConnectorError("Auth0 request failed after retries") from exc
                time.sleep(.1*(attempt+1));continue
            if response.status_code not in {429,500,502,503,504}:break
            if attempt<2:time.sleep(.1*(attempt+1))
        if response is None or response.status_code>=400:raise ConnectorError(f"Auth0 request failed ({response.status_code if response else 'network'})")
        return response
    def _access_token(self):
        if self._token and time.time()<self._token_expires_at:return self._token
        if not self.client_id or not self.client_secret or self.client_secret=="PASTE_YOUR_SECRET_HERE":raise ConnectorError("Auth0 connector credentials are not configured")
        response=self._request("POST",f"https://{self.domain}/oauth/token",json={"grant_type":"client_credentials","client_id":self.client_id,"client_secret":self.client_secret,"audience":f"https://{self.domain}/api/v2/"})
        payload=response.json();self._token=payload["access_token"];self._token_expires_at=time.time()+max(30,int(payload.get("expires_in",3600))-60);return self._token
    def execute(self,action,subject,idempotency_key,dry_run=True):
        if action not in self.supported_actions:raise ConnectorError(f"Auth0 connector does not support action: {action}")
        target=self._target(subject);correlation_id=f"cirt-{uuid.uuid5(uuid.NAMESPACE_URL,idempotency_key).hex[:24]}"
        if dry_run:return ConnectorResult("DRY_RUN",correlation_id,f"Validated allowlisted Auth0 target {target}; no external system modified.")
        headers={"Authorization":f"Bearer {self._access_token()}","X-Correlation-ID":correlation_id}
        users=self._request("GET",f"https://{self.domain}/api/v2/users-by-email",headers=headers,params={"email":target}).json()
        if len(users)!=1:raise ConnectorError("Auth0 allowlisted target was not found uniquely")
        self._request("PATCH",f"https://{self.domain}/api/v2/users/{quote(users[0]['user_id'],safe='')}",headers=headers,json={"blocked":True})
        return ConnectorResult("SUCCEEDED",correlation_id,f"Blocked allowlisted Auth0 sandbox user {target}.")
    def status(self,provider_request_id):return ConnectorResult("SUBMITTED",provider_request_id,"Check the Auth0 tenant log using the correlation ID.")

def build_connector():
    if settings.connector_mode.lower()=="auth0":return Auth0IdentityConnector(settings.oidc_issuer,settings.auth0_management_client_id,settings.auth0_management_client_secret,settings.auth0_allowed_target_users,settings.auth0_connector_target_user)
    return FakeIdentityConnector()
connector=build_connector()
