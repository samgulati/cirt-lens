"""Deterministic correlation benchmark with benign noise and real suspicious clusters."""
import json,time
from datetime import datetime,timedelta
from app.models import Event
from app.services.correlation_engine import correlation_metrics

def make_event(index,when,user,host,source_ip,destination_ip,flags):
    return Event(id=f"BENCH-{index}",timestamp=when,source="Network",user=user,host=host,source_ip=source_ip,activity="benchmark observation",risk_score=25,risk_flags=json.dumps(flags),data=json.dumps({"destination_ip":destination_ip}))

def workload(noise=5000,clusters=20):
    start=datetime(2026,1,1)
    events=[make_event(i,start+timedelta(seconds=i),f"noise-{i}",f"host-{i}",f"10.{i//65536}.{(i//256)%256}.{i%256}",f"198.18.{(i//256)%256}.{i%256}",["NOISE"]) for i in range(noise)]
    for cluster in range(clusters):
        base=start+timedelta(minutes=cluster)
        for offset in range(4):events.append(make_event(noise+cluster*4+offset,base+timedelta(seconds=offset*20),f"actor-{cluster}",f"asset-{cluster}",f"203.0.113.{cluster+1}",f"192.0.2.{cluster+1}",["SUSPICIOUS_POWERSHELL","CREDENTIAL_ACCESS"]))
    return events

if __name__=="__main__":
    events=workload();started=time.perf_counter();metrics=correlation_metrics(events);metrics["elapsed_ms"]=round((time.perf_counter()-started)*1000,2);metrics["all_pairs"]=len(events)*(len(events)-1)//2;metrics["candidate_reduction_percent"]=round((1-metrics["candidate_pairs"]/metrics["all_pairs"])*100,4);print(json.dumps(metrics,sort_keys=True))
    if metrics["groups"]!=20:raise SystemExit(f'Expected 20 suspicious groups, found {metrics["groups"]}')
    if metrics["candidate_reduction_percent"]<99:raise SystemExit("Correlation candidate reduction fell below 99%")
    if metrics["elapsed_ms"]>5000:raise SystemExit("5,080-event correlation benchmark exceeded the 5-second CI guardrail")
