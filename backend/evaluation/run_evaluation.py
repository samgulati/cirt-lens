"""Deterministic labeled evaluation for detection, correlation, and AI grounding."""
import argparse,json
from datetime import datetime,timedelta
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.config import settings
from app.database import Base
from app.seed.seed_data import BASELINE_DEVICES
from app.services.pipeline import process_raw_telemetry
from app.services.scenario_generator import generate_raw_scenario
from app.schemas.telemetry import AuthenticationEventInput,CloudEventInput,EndpointEventInput,NetworkEventInput
from app.services.investigation_ai import validate_structure

QUALITY_THRESHOLDS={"precision":0.95,"recall":0.95,"classification_accuracy":0.95,"correlation_group_accuracy":0.95,"ai_grounding_validation_accuracy":1.0}

def events_for(case,index,when):
    scenario=case["scenario"]
    if scenario in {"credential","endpoint","exfiltration"}:return generate_raw_scenario(scenario,20000+index,when)
    if scenario=="benign-auth":return [AuthenticationEventInput(id=f"AUTH-BENIGN-{index}",timestamp=when,user="alice@example.com",source_ip=f"10.10.4.{index%200+20}",country="India",city="Bangalore",device_id="DEVICE-ALICE-MAC",result="SUCCESS",mfa_result="APPROVED",authentication_method="FIDO2")]
    if scenario=="benign-endpoint":return [EndpointEventInput(id=f"ENDP-BENIGN-{index}",timestamp=when,hostname=f"DEV-MAC-{index:03d}",user="sam@example.com",process_name="code",parent_process="launchd",command_line="code project",process_hash=f"known-good-{index}",event_type="PROCESS_START")]
    if scenario=="benign-network":return [NetworkEventInput(id=f"NET-BENIGN-{index}",timestamp=when,source_ip=f"10.20.1.{index%200+10}",destination_ip="198.18.0.10",destination_port=443,protocol="HTTPS",bytes_sent=2048,bytes_received=8192,domain="updates.example.test",country="India",user="sam@example.com",hostname=f"DEV-MAC-{index:03d}")]
    if scenario=="benign-cloud":return [CloudEventInput(id=f"CLOUD-BENIGN-{index}",timestamp=when,user="priya@example.com",source_ip=f"10.30.1.{index%200+10}",service="ObjectStorage",action="ListResources",resource="general-documents",result="SUCCESS",privileged=False,sensitive_resource=False,device_id="DEVICE-PRIYA-LNX")]
    if scenario=="near-miss-mfa":return [AuthenticationEventInput(id=f"AUTH-NEAR-{index}-{offset}",timestamp=when+timedelta(minutes=offset),user="alice@example.com",source_ip="10.10.4.22",country="India",city="Bangalore",device_id="DEVICE-ALICE-MAC",result="FAILURE",mfa_result="DENIED",authentication_method="Push MFA") for offset in range(settings.mfa_fatigue_threshold-1)]
    if scenario=="near-miss-egress":return [NetworkEventInput(id=f"NET-NEAR-{index}",timestamp=when,source_ip="10.30.8.8",destination_ip="198.18.0.20",destination_port=443,protocol="TLS",bytes_sent=settings.unusual_egress_bytes-1,bytes_received=9000,domain="backup.example.test",country="India",user="priya@example.com",hostname="OPS-LNX-008")]
    raise ValueError(f"Unknown evaluation scenario: {scenario}")

def expanded_cases(dataset):
    for template in dataset:
        for repetition in range(template.get("repetitions",1)):
            yield {**template,"name":f'{template["name"]}-{repetition+1:02d}'}

def run(output_path=None,enforce=True):
    templates=json.loads((Path(__file__).parent/"dataset.json").read_text());dataset=list(expanded_cases(templates));engine=create_engine("sqlite://",poolclass=StaticPool,connect_args={"check_same_thread":False});Base.metadata.create_all(engine);db=sessionmaker(bind=engine)();tp=fp=fn=tn=0;details=[]
    for index,case in enumerate(dataset):
        when=datetime(2026,1,1)+timedelta(hours=index*3);incidents,findings,_=process_raw_telemetry(db,events_for(case,index,when),BASELINE_DEVICES);predicted=bool(incidents);tp+=int(predicted and case["positive"]);fp+=int(predicted and not case["positive"]);fn+=int(not predicted and case["positive"]);tn+=int(not predicted and not case["positive"]);incident=incidents[0] if incidents else None;flags={x.flag for x in findings};techniques=json.loads(incident.techniques) if incident else [];technique_ids={x["id"] for x in techniques};evidence_ids=set(json.loads(incident.event_ids)) if incident else set();grounded=all(set(item["evidence_ids"])<=evidence_ids for item in techniques);classification_correct=bool(incident and incident.incident_type==case["expected_type"]) if case["positive"] else not predicted;expected_evidence=set(case["expected_flags"])<=flags and set(case["expected_techniques"])<=technique_ids;passed=classification_correct and expected_evidence and grounded
        details.append({"name":case["name"],"label":"positive" if case["positive"] else "negative","passed":passed,"predicted_incident":predicted,"classification_correct":classification_correct,"evidence_grounded":grounded})
    grounding_checks=[(validate_structure({"claims":[{"text":"Observed event","evidence_ids":["EVT-1"]}]},["EVT-1"]),True),(validate_structure({"claims":[{"text":"Invented event","evidence_ids":["EVT-999"]}]},["EVT-1"]),False),(validate_structure({"claims":[]},["EVT-1"]),False),(validate_structure({"claims":[{"text":"Two observations","evidence_ids":["EVT-1","EVT-2"]}]},["EVT-1","EVT-2"]),True)]
    grounding_accuracy=sum(check["fully_grounded_structure_valid"]==expected for check,expected in grounding_checks)/len(grounding_checks);precision=tp/(tp+fp) if tp+fp else 0;recall=tp/(tp+fn) if tp+fn else 0
    result={"dataset":{"templates":len(templates),"cases":len(dataset),"positive":sum(case["positive"] for case in dataset),"negative":sum(not case["positive"] for case in dataset)},"confusion_matrix":{"true_positive":tp,"false_positive":fp,"false_negative":fn,"true_negative":tn},"precision":precision,"recall":recall,"classification_accuracy":sum(item["passed"] for item in details)/len(details),"correlation_group_accuracy":(tp+tn)/len(details),"ai_grounding_validation_accuracy":grounding_accuracy,"thresholds":QUALITY_THRESHOLDS,"cases":details}
    rendered=json.dumps(result,indent=2);print(rendered)
    if output_path:path=Path(output_path);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(rendered+"\n")
    failures={metric:{"actual":result[metric],"required":minimum} for metric,minimum in QUALITY_THRESHOLDS.items() if result[metric]<minimum}
    if enforce and failures:print(json.dumps({"quality_gate":"failed","failures":failures},indent=2));raise SystemExit(1)
    return result

if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--output");parser.add_argument("--no-enforce",action="store_true");args=parser.parse_args();run(args.output,not args.no_enforce)
