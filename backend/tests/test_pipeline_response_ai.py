import json
from datetime import timedelta

from app.models import Event
from app.seed.seed_data import BASELINE_DEVICES
from app.services.correlation_engine import connected_groups, connection_score
from app.services.investigation_ai import investigate, local_answer, validate_citations
from app.services.pipeline import process_raw_telemetry
from app.services.playbook_engine import residual_risk
from app.services.scenario_generator import generate_raw_scenario


def test_full_credential_pipeline(db, now):
    raw = generate_raw_scenario("credential", 9001, now)
    incidents, findings, events = process_raw_telemetry(db, raw, BASELINE_DEVICES)
    assert len(incidents) == 1
    incident = incidents[0]
    flags = {f.flag for f in findings}
    assert {"IMPOSSIBLE_TRAVEL", "MFA_FATIGUE"} <= flags
    assert incident.incident_type == "Credential Compromise"
    assert sum(json.loads(incident.score_breakdown).values()) == incident.risk_score
    assert json.loads(incident.recommended_actions)
    assert all(
        set(t["evidence_ids"]) <= set(json.loads(incident.event_ids))
        for t in json.loads(incident.techniques)
    )


def test_each_scenario_derived(db, now):
    expected = {
        "credential": "Credential Compromise",
        "endpoint": "Endpoint Compromise",
        "exfiltration": "Potential Data Exfiltration",
    }
    for index, (kind, name) in enumerate(expected.items()):
        incidents, _, _ = process_raw_telemetry(
            db,
            generate_raw_scenario(kind, 9100 + index, now + timedelta(hours=index * 2)),
            BASELINE_DEVICES,
        )
        assert incidents[0].incident_type == name


def test_reprocessing_does_not_duplicate(db, now):
    raw = generate_raw_scenario("endpoint", 9200, now)
    first, _, _ = process_raw_telemetry(db, raw, BASELINE_DEVICES)
    second, _, _ = process_raw_telemetry(db, raw, BASELINE_DEVICES)
    assert first[0].id == second[0].id


def test_incremental_ingestion_uses_historical_context(db, now):
    chain = generate_raw_scenario("credential", 9250, now)
    first = next(
        e for e in chain if getattr(e, "country", None) == "India" and e.result == "SUCCESS"
    )
    second = next(
        e for e in chain if getattr(e, "country", None) == "Germany" and e.result == "SUCCESS"
    )
    process_raw_telemetry(db, [first], BASELINE_DEVICES)
    incidents, findings, _ = process_raw_telemetry(db, [second], BASELINE_DEVICES)
    assert "IMPOSSIBLE_TRAVEL" in {f.flag for f in findings}
    assert not incidents  # two signals are intentionally required before incident creation


def test_unrelated_events_do_not_correlate(db, now):
    a = Event(
        id="A",
        timestamp=now,
        source="Endpoint",
        user="a",
        host="H1",
        source_ip="1",
        activity="x",
        risk_score=10,
        risk_flags='["X"]',
        data='{"destination_ip":"2"}',
    )
    b = Event(
        id="B",
        timestamp=now,
        source="Endpoint",
        user="b",
        host="H2",
        source_ip="3",
        activity="x",
        risk_score=10,
        risk_flags='["Y"]',
        data='{"destination_ip":"4"}',
    )
    assert connection_score(a, b) < 5 and not connected_groups([a, b])


def test_same_user_far_apart_not_correlated(now):
    a = Event(
        id="A",
        timestamp=now,
        source="Endpoint",
        user="a",
        host="H",
        source_ip="1",
        activity="x",
        risk_score=10,
        risk_flags='["X"]',
        data="{}",
    )
    b = Event(
        id="B",
        timestamp=now + timedelta(hours=2),
        source="Endpoint",
        user="a",
        host="H",
        source_ip="1",
        activity="x",
        risk_score=10,
        risk_flags='["Y"]',
        data="{}",
    )
    assert connection_score(a, b) == 0


def test_residual_risk_and_original_immutable():
    actions = [{"action": "Revoke active sessions", "status": "EXECUTED"}]
    original = 88
    assert residual_risk(original, actions) == 76 and original == 88


def test_citation_validation():
    assert validate_citations("See AUTH-1", ["AUTH-1"])[0]
    assert not validate_citations("See AUTH-999", ["AUTH-1"])[0]


def test_local_ai_question_specific(db, now):
    incidents, _, events = process_raw_telemetry(
        db, generate_raw_scenario("credential", 9300, now), BASELINE_DEVICES
    )
    answer = local_answer(incidents[0], events, "What evidence supports this?")
    assert "Evidence supporting" in answer and "AUTH-" in answer


def test_external_ai_structured_evidence_accepted(db, now, monkeypatch):
    incident, _, events = process_raw_telemetry(
        db, generate_raw_scenario("credential", 9400, now), BASELINE_DEVICES
    )
    valid_id = json.loads(incident[0].event_ids)[0]
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setattr(
        "app.services.investigation_ai._external",
        lambda *args: {
            "summary": "Grounded summary",
            "claims": [{"text": "Observed evidence", "evidence_ids": [valid_id]}],
            "uncertainties": [],
            "recommended_next_steps": [],
        },
    )
    result = investigate(incident[0], events, "What happened?")
    assert result["mode"] == "openai" and result["validated"]


def test_external_ai_plain_string_is_never_trusted(db, now, monkeypatch):
    incident, _, events = process_raw_telemetry(
        db, generate_raw_scenario("credential", 9450, now), BASELINE_DEVICES
    )
    valid_id = json.loads(incident[0].event_ids)[0]
    calls = []
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setattr(
        "app.services.investigation_ai._external",
        lambda *args: (calls.append(1) or f"Facts supported by {valid_id}"),
    )
    result = investigate(incident[0], events, "What happened?")
    assert len(calls) == 2 and result["mode"] == "local_fallback"


def test_external_ai_invalid_citations_retry_then_fallback(db, now, monkeypatch):
    incident, _, events = process_raw_telemetry(
        db, generate_raw_scenario("credential", 9500, now), BASELINE_DEVICES
    )
    calls = []
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setattr(
        "app.services.investigation_ai._external",
        lambda *args: (calls.append(1) or "See AUTH-999999"),
    )
    result = investigate(incident[0], events, "What happened?")
    assert len(calls) == 2 and result["mode"] == "local_fallback" and result["validated"]
