from collections import defaultdict,Counter
from datetime import datetime,UTC
import hashlib,json,uuid
from ..config import settings
from ..models import Incident,IncidentRiskHistory
from .risk_engine import calculate_risk,calculate_confidence,severity
from .attack_mapping import map_techniques
from .playbook_engine import recommend_playbook,residual_risk

def _data(event): return json.loads(event.data)
def connection_score(left,right):
    a,b=_data(left),_data(right); gap=abs((left.timestamp-right.timestamp).total_seconds())
    if gap>settings.correlation_window_minutes*60:return 0
    score=0
    if left.user and left.user==right.user:score+=4
    if left.host and left.host==right.host:score+=4
    if a.get("device_id") and a.get("device_id")==b.get("device_id"):score+=3
    if left.source_ip and left.source_ip==right.source_ip:score+=3
    if ({left.source_ip,a.get("destination_ip")}-{None})&({right.source_ip,b.get("destination_ip")}-{None}):score+=2
    return score+(3 if gap<=900 else 1)

def group_cohesion(group):
    # Cohesion measures the whole component, so disconnected pairs contribute
    # zero rather than disappearing from the denominator.
    scores=[connection_score(a,b) for i,a in enumerate(group) for b in group[i+1:]]
    return sum(scores)/len(scores) if scores else 0

def candidate_pairs(events):
    buckets=defaultdict(list)
    for event in events:
        data=_data(event)
        for key in filter(None,[f"u:{event.user}" if event.user else None,f"h:{event.host}" if event.host else None,f"s:{event.source_ip}" if event.source_ip else None,f"d:{data.get('device_id')}" if data.get('device_id') else None,f"ip:{data.get('destination_ip')}" if data.get('destination_ip') else None]): buckets[key].append(event)
    return {tuple(sorted((left.id,right.id))) for bucket in buckets.values() for i,left in enumerate(bucket) for right in bucket[i+1:]}

def connected_groups(events):
    # Candidate buckets avoid comparing events that share no entity anchor.
    pairs=candidate_pairs(events); adjacency=defaultdict(set)
    by_id={e.id:e for e in events}
    for left_id,right_id in pairs:
        if connection_score(by_id[left_id],by_id[right_id])>=settings.correlation_min_score: adjacency[left_id].add(right_id);adjacency[right_id].add(left_id)
    visited=set();groups=[]
    for event in events:
        if event.id in visited:continue
        stack=[event.id];component=[]
        while stack:
            eid=stack.pop()
            if eid in visited:continue
            visited.add(eid);component.append(by_id[eid]);stack.extend(adjacency[eid]-visited)
        component=sorted(component,key=lambda e:e.timestamp)
        span=(component[-1].timestamp-component[0].timestamp).total_seconds()/60 if len(component)>1 else 0
        if len(component)>=2 and span<=settings.max_incident_span_minutes and group_cohesion(component)>=settings.min_group_cohesion_score:groups.append(component)
    return groups

def infer_incident_type(flags):
    flags=set(flags)
    if "IMPOSSIBLE_TRAVEL" in flags and flags&{"MFA_FATIGUE","NEW_DEVICE"}:
        context="repeated denied MFA prompts" if "MFA_FATIGUE" in flags else "an untrusted device"
        return "Credential Compromise",f"Credential compromise indicators involving {context}",f"Successful impossible-travel authentication was correlated with {context}; credential compromise remains an analyst hypothesis."
    if "SUSPICIOUS_POWERSHELL" in flags and flags&{"CREDENTIAL_ACCESS","KNOWN_MALICIOUS_IP"}:
        context="credential-store access" if "CREDENTIAL_ACCESS" in flags else "a known demo threat destination"
        return "Endpoint Compromise",f"Suspicious PowerShell correlated with {context}",f"Suspicious PowerShell execution was correlated with {context}; endpoint compromise remains an analyst hypothesis."
    if "UNUSUAL_EGRESS" in flags and flags&{"SENSITIVE_RESOURCE_ACCESS","MASS_DOWNLOAD","DATA_EXFILTRATION"}:
        evidence=[]
        if flags&{"SENSITIVE_RESOURCE_ACCESS","MASS_DOWNLOAD"}:evidence.append("sensitive-resource activity")
        if "DATA_EXFILTRATION" in flags:evidence.append("high-volume outbound transfer")
        context=" and ".join(evidence)
        return "Potential Data Exfiltration",f"Potential data exfiltration involving {context}",f"Unusual egress was correlated with {context}; exfiltration remains an analyst hypothesis."
    return "Suspicious Activity","Correlated suspicious activity","Multiple related detections require analyst investigation."

def fingerprint(tenant_id,incident_type,principal,start):
    bucket=int(start.timestamp()//(settings.max_incident_span_minutes*60));return hashlib.sha256(f"{tenant_id}|{incident_type}|{principal}|{bucket}".encode()).hexdigest()[:24]

def build_correlation_graph(events):
    nodes={};edges={}
    def node(kind,value,event):
        if not value:return None
        key=f"{kind}:{value}"; item=nodes.setdefault(key,{"id":key,"type":kind,"value":value,"evidence_ids":[],"risk_flags":[]})
        if event.id not in item["evidence_ids"]:item["evidence_ids"].append(event.id)
        item["risk_flags"]=sorted(set(item["risk_flags"]+json.loads(event.risk_flags)));return key
    def edge(a,b,relationship,event,score):
        if not a or not b:return
        key=f"{a}|{b}|{relationship}";item=edges.setdefault(key,{"id":key,"from":a,"to":b,"relationship":relationship,"score":score,"evidence_ids":[]})
        if event.id not in item["evidence_ids"]:item["evidence_ids"].append(event.id)
    for event in events:
        d=_data(event);user=node("user",event.user,event);device=node("device",d.get("device_id"),event);host=node("host",event.host,event);source=node("source_ip",event.source_ip,event);destination=node("destination_ip",d.get("destination_ip"),event);resource=node("cloud_resource",d.get("resource"),event)
        edge(user,device,"authenticated_from_device",event,4);edge(user,host,"observed_on_host",event,4);edge(host or device,source,"used_source_ip",event,3);edge(source,destination,"connected_to",event,2);edge(user,resource,"accessed_resource",event,4)
    return {"nodes":list(nodes.values()),"edges":list(edges.values())}

def create_or_update_incidents(db,suspicious_events,findings):
    by_event=defaultdict(list)
    for item in findings:by_event[item.event_id].append(item)
    results=[]
    for group in connected_groups(suspicious_events):
        tenant_id=group[0].tenant_id
        ids=[e.id for e in group]; group_findings=[f for eid in ids for f in by_event[eid]];flags=[f.flag for f in group_findings]
        if len(set(flags))<2:continue
        users=[e.user for e in group if e.user];hosts=[e.host for e in group if e.host];principal=Counter(users or hosts).most_common(1)[0][0];incident_type,title,root=infer_incident_type(flags);fp=fingerprint(tenant_id,incident_type,principal,group[0].timestamp)
        existing=db.query(Incident).filter(Incident.tenant_id==tenant_id,Incident.incident_fingerprint==fp,Incident.status.in_(["NEW","INVESTIGATING"])).first()
        if not existing:
            # A later batch can strengthen a generic case and change its
            # classification/fingerprint. Reuse an open case sharing evidence.
            for candidate in db.query(Incident).filter(Incident.tenant_id==tenant_id,Incident.status.in_(["NEW","INVESTIGATING"])).all():
                if set(json.loads(candidate.event_ids))&set(ids): existing=candidate;break
        all_group=group
        if existing:
            combined=sorted(set(json.loads(existing.event_ids)+ids));existing_events={e.id:e for e in group}
            from ..models import Event
            for e in db.query(Event).filter(Event.tenant_id==tenant_id,Event.id.in_(combined)):existing_events[e.id]=e
            all_group=sorted(existing_events.values(),key=lambda e:e.timestamp);ids=[e.id for e in all_group]
            # Rehydrate all persisted findings for full recalculation.
            from ..models import DetectionFindingRecord
            persisted=db.query(DetectionFindingRecord).filter(DetectionFindingRecord.event_id.in_(ids)).all()
            from ..schemas.telemetry import DetectionFinding
            group_findings=[DetectionFinding(event_id=x.event_id,rule_id=x.rule_id,rule_version=x.rule_version,flag=x.flag,risk_contribution=x.risk_contribution,reason=x.reason,metadata=json.loads(x.metadata_json)) for x in persisted]
        flags=[f.flag for f in group_findings];users=[e.user for e in all_group if e.user];hosts=[e.host for e in all_group if e.host];principal=Counter(users or hosts).most_common(1)[0][0];incident_type,title,root=infer_incident_type(flags);fp=fingerprint(tenant_id,incident_type,principal,all_group[0].timestamp)
        cohesion=group_cohesion(all_group);risk,breakdown=calculate_risk(group_findings,all_group);confidence,confidence_parts=calculate_confidence(group_findings,all_group,cohesion)
        techniques=map_techniques(group_findings);actions=recommend_playbook(flags)
        if existing:
            prior={a["action"]:a for a in json.loads(existing.recommended_actions)} if existing.incident_type==incident_type else {}
            for action in actions:
                if action["action"] in prior:action.update({k:v for k,v in prior[action["action"]].items() if k in {"status","executed_at","analyst"}})
            now=datetime.now(UTC).replace(tzinfo=None);old=(existing.risk_score,existing.residual_risk_score,existing.incident_type,set(json.loads(existing.event_ids)))
            if db.query(Incident).filter(Incident.tenant_id==tenant_id,Incident.incident_fingerprint==fp,Incident.id!=existing.id).first():fp=existing.incident_fingerprint
            existing.title=title;existing.incident_type=incident_type;existing.incident_fingerprint=fp;existing.description=f"Correlation linked {len(all_group)} suspicious events, {len(set(flags))} evidence signals, and {len({e.source for e in all_group})} telemetry sources.";existing.root_cause=root;existing.event_ids=json.dumps(ids);existing.updated_at=now;existing.risk_score=risk;existing.residual_risk_score=residual_risk(risk,actions);existing.severity=severity(risk);existing.confidence_score=confidence;existing.confidence_breakdown=json.dumps(confidence_parts);existing.score_breakdown=json.dumps(breakdown);existing.techniques=json.dumps(techniques);existing.recommended_actions=json.dumps(actions);existing.primary_user=Counter(users).most_common(1)[0][0] if users else None;existing.primary_host=Counter(hosts).most_common(1)[0][0] if hosts else None;existing.source_ips=json.dumps(sorted({e.source_ip for e in all_group if e.source_ip}));existing.affected_assets=json.dumps(sorted(set(users+hosts)))
            if old!=(risk,existing.residual_risk_score,incident_type,set(ids)):db.add(IncidentRiskHistory(incident_id=existing.id,timestamp=now,original_risk=risk,residual_risk=existing.residual_risk_score,reason=f"INCIDENT_ENRICHED (previous risk {old[0]}, residual {old[1]}, type {old[2]})"))
            results.append(existing);continue
        if db.query(Incident).filter(Incident.tenant_id==tenant_id,Incident.incident_fingerprint==fp).first():fp=hashlib.sha256(f"{tenant_id}|{fp}|{'|'.join(ids)}".encode()).hexdigest()[:24]
        now=datetime.now(UTC).replace(tzinfo=None);incident_id=f"INC-{uuid.uuid4().hex[:10].upper()}";incident=Incident(id=incident_id,tenant_id=group[0].tenant_id,title=title,incident_type=incident_type,incident_fingerprint=fp,description=f"Correlation linked {len(group)} suspicious events, {len(set(flags))} evidence signals, and {len({e.source for e in group})} telemetry sources.",created_at=now,updated_at=now,severity=severity(risk),status="NEW",risk_score=risk,residual_risk_score=risk,confidence_score=confidence,confidence_breakdown=json.dumps(confidence_parts),primary_user=Counter(users).most_common(1)[0][0] if users else None,primary_host=Counter(hosts).most_common(1)[0][0] if hosts else None,source_ips=json.dumps(sorted({e.source_ip for e in group if e.source_ip})),affected_assets=json.dumps(sorted(set(users+hosts))),event_ids=json.dumps(ids),techniques=json.dumps(techniques),recommended_actions=json.dumps(actions),root_cause=root,score_breakdown=json.dumps(breakdown),disposition="UNSET")
        db.add(incident);db.flush();db.add(IncidentRiskHistory(incident_id=incident.id,timestamp=now,original_risk=risk,residual_risk=risk,reason="INCIDENT_CREATED"));results.append(incident)
    return results

def correlation_metrics(events):
    pairs=candidate_pairs(events);by_id={e.id:e for e in events};edges=sum(connection_score(by_id[a],by_id[b])>=settings.correlation_min_score for a,b in pairs)
    return {"events":len(events),"candidate_pairs":len(pairs),"accepted_edges":edges,"groups":len(connected_groups(events))}
