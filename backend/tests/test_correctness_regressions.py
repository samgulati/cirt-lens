import json
from datetime import timedelta
import pytest
from sqlalchemy.exc import IntegrityError
from app.models import Event,DetectionFindingRecord,IncidentRiskHistory
from app.schemas.telemetry import CloudEventInput
from app.services.correlation_engine import group_cohesion,infer_incident_type
from app.services.detection_engine import detect_new_devices,detect_temporal_privilege
from app.services.pipeline import process_raw_telemetry
from app.services.playbook_engine import select_playbook
from app.services.scenario_generator import generate_raw_scenario
from app.seed.seed_data import BASELINE_DEVICES

def event(i,now,user=None):
    return Event(id=i,timestamp=now,source="Identity",user=user,host=None,source_ip=None,activity="x",risk_score=1,risk_flags="[]",data="{}")

def test_cohesion_includes_zero_pairs(now):
    a=event("A",now,"alice");b=event("B",now,"alice");c=event("C",now+timedelta(hours=2),"bob")
    assert group_cohesion([a,b,c])==pytest.approx(7/3)

def test_failed_new_device_cannot_cause_privilege_escalation(now):
    raw=generate_raw_scenario("credential",9900,now);failed=next(e for e in raw if getattr(e,"result",None)=="FAILURE")
    cloud=CloudEventInput(id="CLOUD-FAIL",timestamp=failed.timestamp+timedelta(minutes=2),user=failed.user,source_ip=failed.source_ip,service="IAM",action="AddRole",resource="role",result="SUCCESS",privileged=True)
    findings=detect_new_devices([failed],BASELINE_DEVICES)
    assert not detect_temporal_privilege([failed,cloud],findings)

@pytest.mark.parametrize("flags,expected",[
 ({"IMPOSSIBLE_TRAVEL","NEW_DEVICE"},"credential"),({"SUSPICIOUS_POWERSHELL","CREDENTIAL_ACCESS"},"endpoint"),({"UNUSUAL_EGRESS","MASS_DOWNLOAD"},"exfiltration")])
def test_playbook_selection_matches_classification(flags,expected):
    incident_type,_,_=infer_incident_type(flags);selected=select_playbook(flags)
    assert selected and selected["id"]==expected and incident_type!="Suspicious Activity"

def test_rule_versions_are_distinct_finding_identity(db,now):
    db.add_all([DetectionFindingRecord(event_id="E",rule_id="R",rule_version=v,flag="F",risk_contribution=1,reason="x",metadata_json="{}",created_at=now) for v in ("1.0","2.0")]);db.commit()
    assert db.query(DetectionFindingRecord).count()==2

def test_cross_batch_full_chain_one_enriched_incident(db,now):
    raw=generate_raw_scenario("credential",9910,now);first=raw[:2];rest=raw[2:]
    process_raw_telemetry(db,first,BASELINE_DEVICES);incidents,_,_=process_raw_telemetry(db,rest,BASELINE_DEVICES)
    assert len({i.id for i in incidents})==1
    incident=incidents[0];assert incident.incident_type=="Credential Compromise"
    assert db.query(IncidentRiskHistory).filter_by(incident_id=incident.id).count()>=1

def test_contained_case_is_not_reopened_by_repeated_scenario(db,now):
    raw=generate_raw_scenario("endpoint",9915,now);first=process_raw_telemetry(db,raw,BASELINE_DEVICES)[0][0];first.status="CONTAINED";db.commit()
    repeated=generate_raw_scenario("endpoint",9916,now);second=process_raw_telemetry(db,repeated,BASELINE_DEVICES)[0][0]
    assert second.id!=first.id and first.status=="CONTAINED" and second.status=="NEW" and second.incident_fingerprint!=first.incident_fingerprint

def test_pipeline_rolls_back_partial_failure(db,now,monkeypatch):
    monkeypatch.setattr("app.services.pipeline.create_or_update_incidents",lambda *args:(_ for _ in ()).throw(RuntimeError("forced")))
    with pytest.raises(RuntimeError):process_raw_telemetry(db,generate_raw_scenario("endpoint",9920,now),BASELINE_DEVICES)
    assert db.query(Event).count()==0 and db.query(DetectionFindingRecord).count()==0
