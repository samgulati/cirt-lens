import json
from fastapi.testclient import TestClient
from app.main import app
from app.database import get_db
from app.auth import seed_identity,hash_password
from app.models import IngestionJob,DetectionRule,ActionApproval,Tenant,UserAccount,Incident
from app.services.pipeline import process_raw_telemetry
from app.services.scenario_generator import generate_raw_scenario
from app.seed.seed_data import BASELINE_DEVICES

def client_for(db):app.dependency_overrides[get_db]=lambda:db;return TestClient(app)
def login(client,email):
    response=client.post('/api/auth/login',json={'email':email,'password':'DemoPass!2026'});assert response.status_code==200;return {'Authorization':'Bearer '+response.json()['access_token']}

def test_local_authentication_and_rbac(db):
    seed_identity(db);client=client_for(db);viewer=login(client,'viewer@demo.local');analyst=login(client,'analyst@demo.local');admin=login(client,'admin@demo.local')
    assert client.get('/api/auth/me',headers=viewer).json()['role']=='VIEWER'
    rule={'rule_id':'CUSTOM-001','version':'1.0','name':'Custom','description':'Draft test rule'}
    assert client.post('/api/rules',json=rule,headers=viewer).status_code==403
    assert client.post('/api/telemetry/ingest',json={'events':[{}]},headers={**analyst,'idempotency-key':'denied-analyst-001'}).status_code==403
    assert client.post('/api/demo/generate',json={'scenario':'credential'},headers=viewer).status_code==403
    assert client.post('/api/rules',json=rule,headers=admin).status_code==201
    app.dependency_overrides.clear()

def test_two_person_approval_rejects_self_approval(db):
    seed_identity(db);incident=process_raw_telemetry(db,generate_raw_scenario('credential',30001),BASELINE_DEVICES)[0][0];client=client_for(db);responder=login(client,'responder@demo.local');admin=login(client,'admin@demo.local')
    requested=client.post(f'/api/incidents/{incident.id}/approvals',json={'action':'Revoke active sessions'},headers=responder);assert requested.status_code==201;approval_id=requested.json()['id']
    assert client.post(f'/api/approvals/{approval_id}/approve',headers=responder).status_code==409
    assert client.post(f'/api/approvals/{approval_id}/approve',headers=admin).status_code==200
    second=process_raw_telemetry(db,generate_raw_scenario('endpoint',30009),BASELINE_DEVICES)[0][0]
    self_requested=client.post(f'/api/incidents/{second.id}/approvals',json={'action':'Isolate host'},headers=admin)
    assert self_requested.status_code==201
    assert client.post(f"/api/approvals/{self_requested.json()['id']}/approve",headers=admin).status_code==409
    assert db.get(ActionApproval,approval_id).status=='APPROVED';app.dependency_overrides.clear()

def test_incident_reads_actions_and_demo_generation_are_tenant_scoped(db,now):
    seed_identity(db)
    incident=process_raw_telemetry(db,generate_raw_scenario('credential',30101,now),BASELINE_DEVICES,tenant_id='tenant-demo')[0][0]
    db.add(Tenant(id='tenant-other',name='Other tenant',created_at=now))
    db.add(UserAccount(id='USR-OTHER-RESPONDER',tenant_id='tenant-other',email='other-responder@demo.local',display_name='Other Responder',role='RESPONDER',password_hash=hash_password('DemoPass!2026'),active=True,created_at=now))
    db.add(UserAccount(id='USR-OTHER-ADMIN',tenant_id='tenant-other',email='other-admin@demo.local',display_name='Other Admin',role='ADMINISTRATOR',password_hash=hash_password('DemoPass!2026'),active=True,created_at=now));db.commit()
    client=client_for(db);responder=login(client,'other-responder@demo.local');admin=login(client,'other-admin@demo.local')
    assert client.get(f'/api/incidents/{incident.id}',headers=responder).status_code==404
    assert client.get('/api/incidents',headers=responder).json()==[]
    assert client.get('/api/dashboard',headers=responder).json()['kpis']['open_incidents']==0
    assert client.get('/api/events',headers=responder).json()==[]
    assert client.post(f'/api/incidents/{incident.id}/approvals',json={'action':'Revoke active sessions'},headers=responder).status_code==404
    generated=client.post('/api/demo/generate',json={'scenario':'credential'},headers=admin);assert generated.status_code==200
    assert db.get(Incident,generated.json()['id']).tenant_id=='tenant-other'
    assert len(client.get('/api/incidents',headers=responder).json())==1
    app.dependency_overrides.clear()

def test_ingestion_idempotency_and_processing_visibility(db,monkeypatch,now):
    seed_identity(db);client=client_for(db);admin=login(client,'admin@demo.local');raw=generate_raw_scenario('endpoint',30002,now)[0].model_dump(mode='json')
    class FakeRedis:
        def xadd(self,*args,**kwargs):return '1-0'
    monkeypatch.setattr('app.platform_api.Redis.from_url',lambda *args,**kwargs:FakeRedis());headers={**admin,'idempotency-key':'same-request-001'}
    first=client.post('/api/telemetry/ingest',json={'events':[raw]},headers=headers);second=client.post('/api/telemetry/ingest',json={'events':[raw]},headers=headers)
    assert first.status_code==202 and not first.json()['deduplicated'];assert second.json()['deduplicated'] and second.json()['job_id']==first.json()['job_id']
    status=client.get('/api/telemetry/jobs/'+first.json()['job_id'],headers=admin).json();assert status['status']=='QUEUED' and status['stream_id']=='1-0';app.dependency_overrides.clear()

def test_rule_lifecycle_and_replay_are_non_mutating(db,now):
    seed_identity(db);client=client_for(db);admin=login(client,'admin@demo.local');rule={'rule_id':'CUSTOM-REPLAY','version':'1.0','name':'Replay','description':'Replay validation'}
    client.post('/api/rules',json=rule,headers=admin);assert client.patch('/api/rules/CUSTOM-REPLAY/1.0/status',json={'status':'ACTIVE'},headers=admin).status_code==409
    assert client.patch('/api/rules/CUSTOM-REPLAY/1.0/status',json={'status':'TESTING'},headers=admin).status_code==200
    assert client.patch('/api/rules/CUSTOM-REPLAY/1.0/status',json={'status':'ACTIVE'},headers=admin).status_code==200
    raw=generate_raw_scenario('endpoint',30003,now);process_raw_telemetry(db,raw,BASELINE_DEVICES,correlate=False);before=db.query(DetectionRule).count();result=client.post('/api/rules/replay',json=[x.id for x in raw],headers=admin)
    assert result.status_code==200 and result.json()['mode']=='NON_MUTATING_REPLAY' and result.json()['database_writes']==0 and db.query(DetectionRule).count()==before;app.dependency_overrides.clear()
