import json
from .correlation_engine import build_correlation_graph

def serialize_event(event):
    return {"id":event.id,"timestamp":event.timestamp.isoformat()+"Z","source":event.source,"user":event.user,"host":event.host,
            "source_ip":event.source_ip,"activity":event.activity,"risk_score":event.risk_score,
            "risk_flags":json.loads(event.risk_flags),"raw":json.loads(event.data)}

def serialize_incident(incident, events=None, db=None):
    result={"id":incident.id,"title":incident.title,"incident_type":incident.incident_type,"description":incident.description,
            "created_at":incident.created_at.isoformat()+"Z","updated_at":incident.updated_at.isoformat()+"Z","severity":incident.severity,
            "status":incident.status,"risk_score":incident.risk_score,"residual_risk_score":incident.residual_risk_score,
            "confidence_score":incident.confidence_score,"primary_user":incident.primary_user,"primary_host":incident.primary_host,
            "source_ips":json.loads(incident.source_ips),"affected_assets":json.loads(incident.affected_assets),"event_ids":json.loads(incident.event_ids),
            "techniques":json.loads(incident.techniques),"recommended_actions":json.loads(incident.recommended_actions),
            "root_cause":incident.root_cause,"score_breakdown":json.loads(incident.score_breakdown),"assigned_to":incident.assigned_to,
            "triaged_at":incident.triaged_at.isoformat()+"Z" if incident.triaged_at else None,
            "incident_fingerprint":incident.incident_fingerprint,"confidence_breakdown":json.loads(incident.confidence_breakdown or "{}"),
            "disposition":incident.disposition}
    if events is not None:
        result["events"]=[serialize_event(e) for e in events]
        result["graph"]=build_correlation_graph(events)
    if db is not None:
        from ..models import AnalystNote,EvidenceBookmark,IncidentRiskHistory,DetectionFindingRecord
        result["notes"]=[{"id":n.id,"analyst":n.analyst,"text":n.text,"timestamp":n.timestamp.isoformat()+"Z"} for n in db.query(AnalystNote).filter_by(incident_id=incident.id).order_by(AnalystNote.timestamp.desc())]
        result["bookmarks"]=[{"id":b.id,"event_id":b.event_id,"analyst":b.analyst,"note":b.note,"timestamp":b.timestamp.isoformat()+"Z"} for b in db.query(EvidenceBookmark).filter_by(incident_id=incident.id).order_by(EvidenceBookmark.timestamp.desc())]
        result["risk_history"]=[{"timestamp":h.timestamp.isoformat()+"Z","original_risk":h.original_risk,"residual_risk":h.residual_risk,"reason":h.reason} for h in db.query(IncidentRiskHistory).filter_by(incident_id=incident.id).order_by(IncidentRiskHistory.timestamp)]
        ids=result["event_ids"]
        result["detection_findings"]=[{"event_id":f.event_id,"rule_id":f.rule_id,"rule_version":f.rule_version,"flag":f.flag,"risk_contribution":f.risk_contribution,"reason":f.reason,"metadata":json.loads(f.metadata_json)} for f in db.query(DetectionFindingRecord).filter(DetectionFindingRecord.event_id.in_(ids)).order_by(DetectionFindingRecord.event_id,DetectionFindingRecord.rule_id)] if ids else []
    return result
