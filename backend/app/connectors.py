"""Replaceable response connectors with an allowlisted Auth0 sandbox implementation."""

import time
import uuid
from dataclasses import dataclass
from urllib.parse import quote

import httpx

from .config import settings


@dataclass(frozen=True)
class ConnectorResult:
    status: str
    provider_request_id: str
    detail: str


class ConnectorError(RuntimeError):
    def __init__(self, message: str, *, code: str = "PROVIDER_ERROR", retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class IdentityConnector:
    name = "identity"

    def execute(self, action, subject, idempotency_key, dry_run=True):
        raise NotImplementedError

    def status(self, provider_request_id):
        raise NotImplementedError


class FakeIdentityConnector(IdentityConnector):
    name = "fake_identity"

    def execute(self, action, subject, idempotency_key, dry_run=True):
        return ConnectorResult(
            "SUCCEEDED",
            f"FAKE-{uuid.uuid5(uuid.NAMESPACE_URL,idempotency_key).hex[:12].upper()}",
            f"{'Dry-run' if dry_run else 'Simulated'} {action} for {subject}; no external system modified.",
        )

    def status(self, provider_request_id):
        return ConnectorResult(
            "SUCCEEDED", provider_request_id, "Deterministic fake provider completed the request."
        )


class Auth0IdentityConnector(IdentityConnector):
    name = "auth0_management"
    supported_actions = {"Disable account"}
    retryable_statuses = {429, 500, 502, 503, 504}

    def __init__(
        self, domain, client_id, client_secret, allowed_users, target_override="", transport=None
    ):
        self.domain = domain.removeprefix("https://").rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.allowed_users = {
            value.strip().lower() for value in allowed_users.split(",") if value.strip()
        }
        self.target_override = target_override.strip().lower()
        self.client = httpx.Client(timeout=8, transport=transport)
        self._token = ""
        self._token_expires_at = 0.0
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0

    def _target(self, subject):
        target = self.target_override or str(subject).strip().lower()
        if not target or target not in self.allowed_users:
            raise ConnectorError("Auth0 target is not explicitly allowlisted")
        return target

    def _request(self, method, url, **kwargs):
        if time.monotonic() < self._circuit_open_until:
            raise ConnectorError(
                "Auth0 connector circuit is open", code="CIRCUIT_OPEN", retryable=True
            )
        response = None
        for attempt in range(3):
            try:
                response = self.client.request(method, url, **kwargs)
            except httpx.RequestError as exc:
                if attempt == 2:
                    self._record_retryable_failure()
                    raise ConnectorError(
                        "Auth0 request failed after retries", code="NETWORK", retryable=True
                    ) from exc
                time.sleep(0.1 * (attempt + 1))
                continue
            if response.status_code not in self.retryable_statuses:
                break
            if attempt < 2:
                time.sleep(0.1 * (attempt + 1))
        if response is None:
            self._record_retryable_failure()
            raise ConnectorError("Auth0 request failed (network)", code="NETWORK", retryable=True)
        if response.status_code in self.retryable_statuses:
            self._record_retryable_failure()
            raise ConnectorError(
                f"Auth0 request failed ({response.status_code})",
                code="UPSTREAM_RETRYABLE",
                retryable=True,
            )
        if response.status_code >= 400:
            raise ConnectorError(
                f"Auth0 request failed ({response.status_code})", code="UPSTREAM_REJECTED"
            )
        self._consecutive_failures = 0
        return response

    def _record_retryable_failure(self):
        self._consecutive_failures += 1
        if self._consecutive_failures >= 2:
            self._circuit_open_until = time.monotonic() + 30

    def _access_token(self):
        if self._token and time.time() < self._token_expires_at:
            return self._token
        if (
            not self.client_id
            or not self.client_secret
            or self.client_secret == "PASTE_YOUR_SECRET_HERE"
        ):
            raise ConnectorError("Auth0 connector credentials are not configured")
        response = self._request(
            "POST",
            f"https://{self.domain}/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "audience": f"https://{self.domain}/api/v2/",
            },
        )
        payload = response.json()
        self._token = payload["access_token"]
        self._token_expires_at = time.time() + max(30, int(payload.get("expires_in", 3600)) - 60)
        return self._token

    def execute(self, action, subject, idempotency_key, dry_run=True):
        if action not in self.supported_actions:
            raise ConnectorError(f"Auth0 connector does not support action: {action}")
        target = self._target(subject)
        correlation_id = f"cirt-{uuid.uuid5(uuid.NAMESPACE_URL,idempotency_key).hex[:24]}"
        if dry_run:
            return ConnectorResult(
                "DRY_RUN",
                correlation_id,
                f"Validated allowlisted Auth0 target {target}; no external system modified.",
            )
        headers = {
            "Authorization": f"Bearer {self._access_token()}",
            "X-Correlation-ID": correlation_id,
        }
        users = self._request(
            "GET",
            f"https://{self.domain}/api/v2/users-by-email",
            headers=headers,
            params={"email": target},
        ).json()
        if len(users) != 1:
            raise ConnectorError("Auth0 allowlisted target was not found uniquely")
        self._request(
            "PATCH",
            f"https://{self.domain}/api/v2/users/{quote(users[0]['user_id'],safe='')}",
            headers=headers,
            json={"blocked": True},
        )
        return ConnectorResult(
            "SUCCEEDED", correlation_id, f"Blocked allowlisted Auth0 sandbox user {target}."
        )

    def status(self, provider_request_id):
        return ConnectorResult(
            "SUBMITTED", provider_request_id, "Check the Auth0 tenant log using the correlation ID."
        )


class RoutedIdentityConnector(IdentityConnector):
    """Routes supported identity mutations to Auth0 and keeps other demo actions simulated."""

    name = "response_router"

    def __init__(self, auth0):
        self.auth0 = auth0
        self.fake = FakeIdentityConnector()

    def execute(self, action, subject, idempotency_key, dry_run=True):
        if action in self.auth0.supported_actions:
            return self.auth0.execute(action, subject, idempotency_key, dry_run)
        return self.fake.execute(action, subject, idempotency_key, True)

    def status(self, provider_request_id):
        return (
            self.auth0.status(provider_request_id)
            if provider_request_id.startswith("cirt-")
            else self.fake.status(provider_request_id)
        )


def build_connector():
    if settings.connector_mode.lower() == "auth0":
        return RoutedIdentityConnector(
            Auth0IdentityConnector(
                settings.oidc_issuer,
                settings.auth0_management_client_id,
                settings.auth0_management_client_secret,
                settings.auth0_allowed_target_users,
                settings.auth0_connector_target_user,
            )
        )
    return FakeIdentityConnector()


connector = build_connector()
