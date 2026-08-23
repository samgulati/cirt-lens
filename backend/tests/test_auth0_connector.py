import httpx,pytest
from app.connectors import Auth0IdentityConnector,ConnectorError

DOMAIN="dev-example.us.auth0.com"
TARGET="connector-target@cirtlens.demo"

def test_auth0_dry_run_never_calls_provider():
    def unexpected(_request):raise AssertionError("dry-run made an external request")
    connector=Auth0IdentityConnector(DOMAIN,"client","secret",TARGET,TARGET,httpx.MockTransport(unexpected))
    result=connector.execute("Disable account","incident-user","tenant:incident:action",dry_run=True)
    assert result.status=="DRY_RUN" and TARGET in result.detail

def test_auth0_rejects_non_allowlisted_target_before_network():
    connector=Auth0IdentityConnector(DOMAIN,"client","secret",TARGET,"",httpx.MockTransport(lambda _:httpx.Response(500)))
    with pytest.raises(ConnectorError,match="allowlisted"):
        connector.execute("Disable account","attacker@example.com","key",dry_run=False)

def test_auth0_live_flow_uses_client_credentials_and_blocks_unique_user():
    seen=[]
    def provider(request):
        seen.append(request)
        if request.url.path=="/oauth/token":return httpx.Response(200,json={"access_token":"management-token","expires_in":3600})
        if request.url.path=="/api/v2/users-by-email":return httpx.Response(200,json=[{"user_id":"auth0|sandbox-user"}])
        if request.method=="PATCH" and request.url.path=="/api/v2/users/auth0|sandbox-user":return httpx.Response(200,json={"blocked":True})
        return httpx.Response(404)
    connector=Auth0IdentityConnector(DOMAIN,"client","secret",TARGET,TARGET,httpx.MockTransport(provider))
    result=connector.execute("Disable account","incident-user","stable-key",dry_run=False)
    assert result.status=="SUCCEEDED" and len(seen)==3
    assert seen[1].headers["authorization"]=="Bearer management-token"
    assert seen[2].headers["x-correlation-id"]==result.provider_request_id
    assert seen[2].read()==b'{"blocked":true}'

def test_auth0_supports_only_truthful_account_disable_action():
    connector=Auth0IdentityConnector(DOMAIN,"client","secret",TARGET,TARGET)
    with pytest.raises(ConnectorError,match="does not support"):
        connector.execute("Revoke active sessions",TARGET,"key",dry_run=True)
