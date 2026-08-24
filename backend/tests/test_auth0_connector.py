import httpx
import pytest
from app.connectors import Auth0IdentityConnector, ConnectorError, RoutedIdentityConnector

DOMAIN = "dev-example.us.auth0.com"
TARGET = "connector-target@cirtlens.demo"


def test_auth0_dry_run_never_calls_provider():
    def unexpected(_request):
        raise AssertionError("dry-run made an external request")

    connector = Auth0IdentityConnector(
        DOMAIN, "client", "secret", TARGET, TARGET, httpx.MockTransport(unexpected)
    )
    result = connector.execute(
        "Disable account", "incident-user", "tenant:incident:action", dry_run=True
    )
    assert result.status == "DRY_RUN" and TARGET in result.detail


def test_auth0_rejects_non_allowlisted_target_before_network():
    connector = Auth0IdentityConnector(
        DOMAIN, "client", "secret", TARGET, "", httpx.MockTransport(lambda _: httpx.Response(500))
    )
    with pytest.raises(ConnectorError, match="allowlisted"):
        connector.execute("Disable account", "attacker@example.com", "key", dry_run=False)


def test_auth0_live_flow_uses_client_credentials_and_blocks_unique_user():
    seen = []

    def provider(request):
        seen.append(request)
        if request.url.path == "/oauth/token":
            return httpx.Response(
                200, json={"access_token": "management-token", "expires_in": 3600}
            )
        if request.url.path == "/api/v2/users-by-email":
            return httpx.Response(200, json=[{"user_id": "auth0|sandbox-user"}])
        if request.method == "PATCH" and request.url.path == "/api/v2/users/auth0|sandbox-user":
            return httpx.Response(200, json={"blocked": True})
        return httpx.Response(404)

    connector = Auth0IdentityConnector(
        DOMAIN, "client", "secret", TARGET, TARGET, httpx.MockTransport(provider)
    )
    result = connector.execute("Disable account", "incident-user", "stable-key", dry_run=False)
    assert result.status == "SUCCEEDED" and len(seen) == 3
    assert seen[1].headers["authorization"] == "Bearer management-token"
    assert seen[2].headers["x-correlation-id"] == result.provider_request_id
    assert seen[2].read() == b'{"blocked":true}'


def test_auth0_supports_only_truthful_account_disable_action():
    connector = Auth0IdentityConnector(DOMAIN, "client", "secret", TARGET, TARGET)
    with pytest.raises(ConnectorError, match="does not support"):
        connector.execute("Revoke active sessions", TARGET, "key", dry_run=True)


def test_router_keeps_non_auth0_actions_safe_and_simulated():
    auth0 = Auth0IdentityConnector(
        DOMAIN,
        "client",
        "secret",
        TARGET,
        TARGET,
        httpx.MockTransport(
            lambda _: (_ for _ in ()).throw(AssertionError("unexpected provider call"))
        ),
    )
    result = RoutedIdentityConnector(auth0).execute("Isolate host", "host-1", "key", dry_run=False)
    assert (
        result.status == "SUCCEEDED"
        and result.provider_request_id.startswith("FAKE-")
        and "no external system modified" in result.detail
    )


def test_auth0_retries_transient_failure_then_recovers(monkeypatch):
    attempts = 0

    def provider(_request):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            return httpx.Response(503)
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr("app.connectors.time.sleep", lambda _: None)
    connector = Auth0IdentityConnector(
        DOMAIN, "client", "secret", TARGET, TARGET, httpx.MockTransport(provider)
    )
    response = connector._request("GET", f"https://{DOMAIN}/health")
    assert response.status_code == 200
    assert attempts == 3
    assert connector._consecutive_failures == 0


def test_auth0_circuit_opens_after_repeated_failed_operations(monkeypatch):
    calls = 0

    def provider(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    monkeypatch.setattr("app.connectors.time.sleep", lambda _: None)
    connector = Auth0IdentityConnector(
        DOMAIN, "client", "secret", TARGET, TARGET, httpx.MockTransport(provider)
    )
    for _ in range(2):
        with pytest.raises(ConnectorError) as failure:
            connector._request("GET", f"https://{DOMAIN}/health")
        assert failure.value.retryable is True
        assert failure.value.code == "UPSTREAM_RETRYABLE"

    with pytest.raises(ConnectorError) as open_circuit:
        connector._request("GET", f"https://{DOMAIN}/health")
    assert open_circuit.value.code == "CIRCUIT_OPEN"
    assert calls == 6


def test_auth0_does_not_retry_provider_rejection(monkeypatch):
    calls = 0

    def provider(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(403)

    monkeypatch.setattr("app.connectors.time.sleep", lambda _: None)
    connector = Auth0IdentityConnector(
        DOMAIN, "client", "secret", TARGET, TARGET, httpx.MockTransport(provider)
    )
    with pytest.raises(ConnectorError) as rejected:
        connector._request("GET", f"https://{DOMAIN}/health")
    assert rejected.value.code == "UPSTREAM_REJECTED"
    assert rejected.value.retryable is False
    assert calls == 1
