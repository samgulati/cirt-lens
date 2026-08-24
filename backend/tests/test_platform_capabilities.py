from datetime import timedelta
from types import SimpleNamespace

from app.auth import hash_password, seed_identity
from app.database import get_db
from app.main import app
from app.models import (
    ActionApproval,
    ConnectorExecution,
    DetectionRule,
    Incident,
    Tenant,
    UserAccount,
)
from app.seed.seed_data import BASELINE_DEVICES
from app.services.pipeline import process_raw_telemetry
from app.services.scenario_generator import generate_raw_scenario
from fastapi.testclient import TestClient


def client_for(db):
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


def login(client, email):
    response = client.post("/api/auth/login", json={"email": email, "password": "DemoPass!2026"})
    assert response.status_code == 200
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def test_local_authentication_and_rbac(db):
    seed_identity(db)
    client = client_for(db)
    viewer = login(client, "viewer@demo.local")
    analyst = login(client, "analyst@demo.local")
    admin = login(client, "admin@demo.local")
    assert client.get("/api/auth/me", headers=viewer).json()["role"] == "VIEWER"
    rule = {
        "rule_id": "CUSTOM-001",
        "version": "1.0",
        "name": "Custom",
        "description": "Draft test rule",
    }
    assert client.post("/api/rules", json=rule, headers=viewer).status_code == 403
    assert (
        client.post(
            "/api/telemetry/ingest",
            json={"events": [{}]},
            headers={**analyst, "idempotency-key": "denied-analyst-001"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/demo/generate", json={"scenario": "credential"}, headers=viewer
        ).status_code
        == 403
    )
    assert client.post("/api/rules", json=rule, headers=admin).status_code == 201
    app.dependency_overrides.clear()


def test_two_person_approval_rejects_self_approval(db):
    seed_identity(db)
    incident = process_raw_telemetry(
        db, generate_raw_scenario("credential", 30001), BASELINE_DEVICES
    )[0][0]
    client = client_for(db)
    responder = login(client, "responder@demo.local")
    admin = login(client, "admin@demo.local")
    requested = client.post(
        f"/api/incidents/{incident.id}/approvals",
        json={"action": "Revoke active sessions"},
        headers=responder,
    )
    assert requested.status_code == 201
    approval_id = requested.json()["id"]
    assert (
        client.post(f"/api/approvals/{approval_id}/approve", headers=responder).status_code == 409
    )
    assert client.post(f"/api/approvals/{approval_id}/approve", headers=admin).status_code == 200
    second = process_raw_telemetry(db, generate_raw_scenario("endpoint", 30009), BASELINE_DEVICES)[
        0
    ][0]
    self_requested = client.post(
        f"/api/incidents/{second.id}/approvals", json={"action": "Isolate host"}, headers=admin
    )
    assert self_requested.status_code == 201
    assert (
        client.post(
            f"/api/approvals/{self_requested.json()['id']}/approve", headers=admin
        ).status_code
        == 409
    )
    assert db.get(ActionApproval, approval_id).status == "APPROVED"
    app.dependency_overrides.clear()


def test_approval_is_time_bound_and_consumed_atomically(db, monkeypatch):
    seed_identity(db)
    incident = process_raw_telemetry(
        db, generate_raw_scenario("credential", 30021), BASELINE_DEVICES
    )[0][0]
    client = client_for(db)
    responder = login(client, "responder@demo.local")
    admin = login(client, "admin@demo.local")
    monkeypatch.setattr(
        "app.services.response_actions.settings",
        SimpleNamespace(auth_required=True, approval_ttl_minutes=30, auth0_connector_live=False),
    )
    requested = client.post(
        f"/api/incidents/{incident.id}/approvals",
        json={"action": "Revoke active sessions"},
        headers=responder,
    )
    approval_id = requested.json()["id"]
    assert client.post(f"/api/approvals/{approval_id}/approve", headers=admin).status_code == 200
    executed = client.post(
        f"/api/incidents/{incident.id}/actions",
        json={"action": "Revoke active sessions"},
        headers=responder,
    )
    assert executed.status_code == 200
    assert db.get(ActionApproval, approval_id).status == "CONSUMED"

    endpoint_incidents = process_raw_telemetry(
        db, generate_raw_scenario("endpoint", 30022), BASELINE_DEVICES
    )[0]
    expired_incident = next(
        value for value in endpoint_incidents if value.incident_type == "Endpoint Compromise"
    )
    expired_request = client.post(
        f"/api/incidents/{expired_incident.id}/approvals",
        json={"action": "Isolate host"},
        headers=responder,
    )
    expired_id = expired_request.json()["id"]
    assert client.post(f"/api/approvals/{expired_id}/approve", headers=admin).status_code == 200
    expired = db.get(ActionApproval, expired_id)
    expired.decided_at -= timedelta(minutes=31)
    db.commit()
    denied = client.post(
        f"/api/incidents/{expired_incident.id}/actions",
        json={"action": "Isolate host"},
        headers=responder,
    )
    assert denied.status_code == 409 and "expired" in denied.json()["error"]["detail"]
    assert db.get(ActionApproval, expired_id).status == "EXPIRED"
    app.dependency_overrides.clear()


def test_incident_reads_actions_and_demo_generation_are_tenant_scoped(db, now):
    seed_identity(db)
    incident = process_raw_telemetry(
        db,
        generate_raw_scenario("credential", 30101, now),
        BASELINE_DEVICES,
        tenant_id="tenant-demo",
    )[0][0]
    db.add(Tenant(id="tenant-other", name="Other tenant", created_at=now))
    db.add(
        UserAccount(
            id="USR-OTHER-RESPONDER",
            tenant_id="tenant-other",
            email="other-responder@demo.local",
            display_name="Other Responder",
            role="RESPONDER",
            password_hash=hash_password("DemoPass!2026"),
            active=True,
            created_at=now,
        )
    )
    db.add(
        UserAccount(
            id="USR-OTHER-ADMIN",
            tenant_id="tenant-other",
            email="other-admin@demo.local",
            display_name="Other Admin",
            role="ADMINISTRATOR",
            password_hash=hash_password("DemoPass!2026"),
            active=True,
            created_at=now,
        )
    )
    db.commit()
    client = client_for(db)
    responder = login(client, "other-responder@demo.local")
    admin = login(client, "other-admin@demo.local")
    demo_admin = login(client, "admin@demo.local")
    assert client.get(f"/api/incidents/{incident.id}", headers=responder).status_code == 404
    assert client.get("/api/incidents", headers=responder).json() == []
    assert client.get("/api/dashboard", headers=responder).json()["kpis"]["open_incidents"] == 0
    assert client.get("/api/events", headers=responder).json() == []
    assert client.get("/api/approvals", headers=responder).json() == []
    assert client.get("/api/telemetry/jobs", headers=responder).json() == []
    assert (
        client.post(
            f"/api/incidents/{incident.id}/approvals",
            json={"action": "Revoke active sessions"},
            headers=responder,
        ).status_code
        == 404
    )
    other_incident = process_raw_telemetry(
        db,
        generate_raw_scenario("credential", 30102, now),
        BASELINE_DEVICES,
        tenant_id="tenant-other",
    )[0][0]
    assert other_incident.id != incident.id and other_incident.tenant_id == "tenant-other"
    assert db.get(Incident, incident.id).tenant_id == "tenant-demo"
    custom_rule = {
        "rule_id": "TENANT-DEMO-ONLY",
        "version": "1.0",
        "name": "Tenant boundary",
        "description": "Must never cross the tenant boundary",
    }
    assert client.post("/api/rules", json=custom_rule, headers=demo_admin).status_code == 201
    other_rule_ids = {item["rule_id"] for item in client.get("/api/rules", headers=admin).json()}
    assert "TENANT-DEMO-ONLY" not in other_rule_ids
    db.add(
        ConnectorExecution(
            id="CON-DEMO-ONLY",
            tenant_id="tenant-demo",
            incident_id=incident.id,
            action="Disable account",
            connector="fake_identity",
            idempotency_key="tenant-demo:connector-only",
            provider_request_id="FAKE-DEMO",
            status="SUCCEEDED",
            dry_run=True,
            attempts=1,
            detail="tenant boundary fixture",
            created_at=now,
        )
    )
    db.commit()
    assert client.get("/api/connector-executions", headers=responder).json() == []
    assert (
        client.post(
            "/api/connector-executions/CON-DEMO-ONLY/reconcile", headers=responder
        ).status_code
        == 404
    )
    generated = client.post("/api/demo/generate", json={"scenario": "credential"}, headers=admin)
    assert generated.status_code == 200
    assert db.get(Incident, generated.json()["id"]).tenant_id == "tenant-other"
    visible_ids = {item["id"] for item in client.get("/api/incidents", headers=responder).json()}
    assert visible_ids == {other_incident.id, generated.json()["id"]}
    app.dependency_overrides.clear()


def test_ingestion_idempotency_and_processing_visibility(db, monkeypatch, now):
    seed_identity(db)
    client = client_for(db)
    admin = login(client, "admin@demo.local")
    raw = generate_raw_scenario("endpoint", 30002, now)[0].model_dump(mode="json")

    class FakeRedis:
        def xadd(self, *args, **kwargs):
            return "1-0"

    monkeypatch.setattr("app.platform_api.Redis.from_url", lambda *args, **kwargs: FakeRedis())
    headers = {**admin, "idempotency-key": "same-request-001"}
    first = client.post("/api/telemetry/ingest", json={"events": [raw]}, headers=headers)
    second = client.post("/api/telemetry/ingest", json={"events": [raw]}, headers=headers)
    assert first.status_code == 202 and not first.json()["deduplicated"]
    assert second.json()["deduplicated"] and second.json()["job_id"] == first.json()["job_id"]
    status = client.get("/api/telemetry/jobs/" + first.json()["job_id"], headers=admin).json()
    assert status["status"] == "QUEUED" and status["stream_id"] == "1-0"
    app.dependency_overrides.clear()


def test_rule_lifecycle_and_replay_are_non_mutating(db, now):
    seed_identity(db)
    client = client_for(db)
    admin = login(client, "admin@demo.local")
    rule = {
        "rule_id": "CUSTOM-REPLAY",
        "version": "1.0",
        "name": "Replay",
        "description": "Replay validation",
    }
    client.post("/api/rules", json=rule, headers=admin)
    assert (
        client.patch(
            "/api/rules/CUSTOM-REPLAY/1.0/status", json={"status": "ACTIVE"}, headers=admin
        ).status_code
        == 409
    )
    assert (
        client.patch(
            "/api/rules/CUSTOM-REPLAY/1.0/status", json={"status": "TESTING"}, headers=admin
        ).status_code
        == 200
    )
    assert (
        client.patch(
            "/api/rules/CUSTOM-REPLAY/1.0/status", json={"status": "ACTIVE"}, headers=admin
        ).status_code
        == 200
    )
    raw = generate_raw_scenario("endpoint", 30003, now)
    process_raw_telemetry(db, raw, BASELINE_DEVICES, correlate=False)
    before = db.query(DetectionRule).count()
    result = client.post("/api/rules/replay", json=[x.id for x in raw], headers=admin)
    assert (
        result.status_code == 200
        and result.json()["mode"] == "NON_MUTATING_REPLAY"
        and result.json()["database_writes"] == 0
        and db.query(DetectionRule).count() == before
    )
    app.dependency_overrides.clear()
