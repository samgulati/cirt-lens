import json

from app.database import get_db
from app.main import app
from app.models import Activity
from app.seed.seed_data import BASELINE_DEVICES
from app.services.pipeline import process_raw_telemetry
from app.services.scenario_generator import generate_raw_scenario
from fastapi.testclient import TestClient


def client_for(db):
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


def test_generate_fetch_full_api_pipeline(db):
    client = client_for(db)
    response = client.post("/api/demo/generate", json={"scenario": "credential"})
    assert response.status_code == 200
    incident = response.json()
    fetched = client.get("/api/incidents/" + incident["id"]).json()
    flags = {flag for event in fetched["events"] for flag in event["risk_flags"]}
    assert {"IMPOSSIBLE_TRAVEL", "MFA_FATIGUE"} <= flags
    assert sum(fetched["score_breakdown"].values()) == fetched["risk_score"]
    assert fetched["recommended_actions"]
    assert all(set(t["evidence_ids"]) <= set(fetched["event_ids"]) for t in fetched["techniques"])
    app.dependency_overrides.clear()


def test_response_validation_idempotency_audit_and_residual(db, now):
    incident = process_raw_telemetry(
        db, generate_raw_scenario("credential", 9600, now), BASELINE_DEVICES
    )[0][0]
    client = client_for(db)
    original = incident.risk_score
    assert (
        client.post(
            f"/api/incidents/{incident.id}/actions", json={"action": "Not allowed"}
        ).status_code
        == 400
    )
    first = client.post(
        f"/api/incidents/{incident.id}/actions", json={"action": "Revoke active sessions"}
    )
    assert first.status_code == 200
    body = first.json()["incident"]
    assert body["risk_score"] == original and body["residual_risk_score"] == original - 12
    assert (
        client.post(
            f"/api/incidents/{incident.id}/actions", json={"action": "Revoke active sessions"}
        ).status_code
        == 409
    )
    assert db.query(Activity).filter(Activity.incident_id == incident.id).count() == 1
    app.dependency_overrides.clear()


def test_non_containment_action_does_not_contain(db, now):
    incident = process_raw_telemetry(
        db, generate_raw_scenario("endpoint", 9700, now), BASELINE_DEVICES
    )[0][0]
    client = client_for(db)
    response = client.post(
        f"/api/incidents/{incident.id}/actions", json={"action": "Collect forensic snapshot"}
    ).json()["incident"]
    assert (
        response["status"] == "INVESTIGATING"
        and response["residual_risk_score"] == response["risk_score"]
    )
    app.dependency_overrides.clear()


def test_status_workflow_cannot_bypass_containment(db, now):
    incident = process_raw_telemetry(
        db, generate_raw_scenario("credential", 9750, now), BASELINE_DEVICES
    )[0][0]
    client = client_for(db)
    assert (
        client.patch(f"/api/incidents/{incident.id}", json={"status": "CONTAINED"}).status_code
        == 409
    )
    assert (
        client.patch(f"/api/incidents/{incident.id}", json={"status": "RESOLVED"}).status_code
        == 409
    )
    assert (
        client.patch(f"/api/incidents/{incident.id}", json={"status": "INVESTIGATING"}).status_code
        == 200
    )
    assert (
        client.patch(f"/api/incidents/{incident.id}", json={"status": "RESOLVED"}).status_code
        == 200
    )
    assert client.patch(f"/api/incidents/{incident.id}", json={"status": "NEW"}).status_code == 409
    app.dependency_overrides.clear()


def test_case_notes_bookmarks_disposition_and_risk_history(db, now):
    incident = process_raw_telemetry(
        db, generate_raw_scenario("credential", 9800, now), BASELINE_DEVICES
    )[0][0]
    client = client_for(db)
    event_id = json.loads(incident.event_ids)[0]
    assert (
        client.post(
            f"/api/incidents/{incident.id}/notes", json={"text": "Confirmed with identity owner."}
        ).status_code
        == 201
    )
    assert (
        client.post(
            f"/api/incidents/{incident.id}/bookmarks",
            json={"event_id": event_id, "note": "Key authentication evidence"},
        ).status_code
        == 201
    )
    assert (
        client.post(
            f"/api/incidents/{incident.id}/bookmarks", json={"event_id": event_id}
        ).status_code
        == 409
    )
    assert (
        client.patch(
            f"/api/incidents/{incident.id}/disposition", json={"disposition": "TRUE_POSITIVE"}
        ).status_code
        == 200
    )
    client.post(f"/api/incidents/{incident.id}/actions", json={"action": "Revoke active sessions"})
    fetched = client.get(f"/api/incidents/{incident.id}").json()
    assert (
        fetched["notes"]
        and fetched["bookmarks"]
        and fetched["disposition"] == "TRUE_POSITIVE"
        and len(fetched["risk_history"]) >= 2
    )
    app.dependency_overrides.clear()
