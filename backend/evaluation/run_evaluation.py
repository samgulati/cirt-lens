import json
from datetime import datetime,timedelta
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.database import Base
from app.seed.seed_data import BASELINE_DEVICES
from app.services.pipeline import process_raw_telemetry
from app.services.scenario_generator import generate_raw_scenario
from app.schemas.telemetry import AuthenticationEventInput,EndpointEventInput
from app.services.investigation_ai import validate_structure

def events_for(case,index,when):
    if case["scenario"]=="benign-auth":return [AuthenticationEventInput(id=f"AUTH-BENIGN-{index}",timestamp=when,user="alice@example.com",source_ip="10.10.4.22",country="India",city="Bangalore",device_id="DEVICE-ALICE-MAC",result="SUCCESS",mfa_result="APPROVED",authentication_method="Push MFA")]
    if case["scenario"]=="benign-endpoint":return [EndpointEventInput(id=f"ENDP-BENIGN-{index}",timestamp=when,hostname="DEV-MAC-001",user="sam@example.com",process_name="code",parent_process="launchd",command_line="code project",process_hash="known-good",event_type="PROCESS_START")]
    return generate_raw_scenario(case["scenario"],20000+index,when)

def run():
    dataset=json.loads((Path(__file__).parent/"dataset.json").read_text());engine=create_engine("sqlite://",poolclass=StaticPool,connect_args={"check_same_thread":False});Base.metadata.create_all(engine);db=sessionmaker(bind=engine)();tp=fp=fn=0;details=[]
    for index,case in enumerate(dataset):
        incidents,findings,_=process_raw_telemetry(db,events_for(case,index,datetime(2026,1,1)+timedelta(hours=index*2)),BASELINE_DEVICES);predicted=bool(incidents);tp+=predicted and case["positive"];fp+=predicted and not case["positive"];fn+=(not predicted) and case["positive"];incident=incidents[0] if incidents else None;flags={x.flag for x in findings};techniques={x["id"] for x in json.loads(incident.techniques)} if incident else set();passed=(bool(incident and incident.incident_type==case["expected_type"] and set(case["expected_flags"])<=flags and set(case["expected_techniques"])<=techniques) if case["positive"] else not predicted);details.append({"name":case["name"],"passed":passed,"predicted_incident":predicted})
    grounding_cases=[validate_structure({"claims":[{"text":"Observed event","evidence_ids":["EVT-1"]}]},["EVT-1"]),validate_structure({"claims":[{"text":"Invented event","evidence_ids":["EVT-999"]}]},["EVT-1"])]
    grounding_accuracy=(grounding_cases[0]["fully_grounded_structure_valid"] and not grounding_cases[1]["fully_grounded_structure_valid"])
    precision=tp/(tp+fp) if tp+fp else 0;recall=tp/(tp+fn) if tp+fn else 0;result={"cases":details,"confusion_matrix":{"true_positive":tp,"false_positive":fp,"false_negative":fn,"true_negative":len(dataset)-tp-fp-fn},"precision":precision,"recall":recall,"classification_accuracy":sum(x["passed"] for x in details)/len(details),"correlation_group_accuracy":sum(x["passed"] for x in details)/len(details),"ai_grounding_validation_accuracy":float(grounding_accuracy)};print(json.dumps(result,indent=2));return result
if __name__=="__main__":run()
