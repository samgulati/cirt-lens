from app.schemas.telemetry import DetectionFinding
from app.services.risk_engine import calculate_risk,severity
from app.services.attack_mapping import map_techniques

def f(event,flag,risk=30): return DetectionFinding(event_id=event,rule_id="R",flag=flag,risk_contribution=risk,reason="reason")
def test_risk_invariant_below_100():
    score,parts=calculate_risk([f("E-1","NEW_DEVICE",10)]); assert score==sum(parts.values())<100
def test_risk_invariant_at_cap():
    findings=[f(str(i),flag) for i,flag in enumerate(["CREDENTIAL_ACCESS","PRIVILEGE_ESCALATION","IMPOSSIBLE_TRAVEL","MFA_FATIGUE","NEW_DEVICE","UNUSUAL_EGRESS","KNOWN_MALICIOUS_IP","DATA_EXFILTRATION"])]
    score,parts=calculate_risk(findings,[{"sensitive_resource":True}]); assert score==sum(parts.values())==100
def test_all_severity_boundaries(): assert [severity(x) for x in [0,24,25,49,50,74,75,100]]==["LOW","LOW","MEDIUM","MEDIUM","HIGH","HIGH","CRITICAL","CRITICAL"]
def test_attack_mapping_specific_evidence():
    techniques=map_techniques([f("ENDP-1","SUSPICIOUS_POWERSHELL"),f("ENDP-2","CREDENTIAL_ACCESS"),f("NET-9","KNOWN_MALICIOUS_IP")])
    assert {t["id"] for t in techniques}=={"T1059.001","T1003"}
    assert all(t["evidence_ids"] and set(t["evidence_ids"])<={"ENDP-1","ENDP-2"} for t in techniques)
