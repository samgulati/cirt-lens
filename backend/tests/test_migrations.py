import os,sqlite3,subprocess,sys
from pathlib import Path

BACKEND=Path(__file__).resolve().parents[1]

def test_fresh_database_is_created_by_explicit_migrations(tmp_path):
    database=tmp_path/'fresh.db';environment={**os.environ,'DATABASE_URL':f'sqlite:///{database}'}
    result=subprocess.run([sys.executable,'-m','alembic','upgrade','head'],cwd=BACKEND,env=environment,capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    connection=sqlite3.connect(database);tables={row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {'events','incidents','activity','detection_findings','analyst_notes','evidence_bookmarks','incident_risk_history'}<=tables
    unique_sql=connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='detection_findings'").fetchone()[0]
    assert 'rule_version' in unique_sql and 'uq_finding_event_rule_version_flag' in unique_sql
    connection.close()

def test_legacy_database_upgrades_without_losing_rows(tmp_path):
    database=tmp_path/'legacy.db';connection=sqlite3.connect(database)
    connection.executescript("""
      CREATE TABLE events (
        id VARCHAR PRIMARY KEY, timestamp DATETIME NOT NULL, source VARCHAR NOT NULL,
        user VARCHAR, host VARCHAR, source_ip VARCHAR, activity VARCHAR NOT NULL,
        risk_score INTEGER NOT NULL DEFAULT 0, risk_flags TEXT NOT NULL DEFAULT '[]', data TEXT NOT NULL DEFAULT '{}'
      );
      CREATE TABLE incidents (
        id VARCHAR PRIMARY KEY, title VARCHAR NOT NULL, description TEXT NOT NULL,
        created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, severity VARCHAR NOT NULL,
        status VARCHAR NOT NULL DEFAULT 'NEW', risk_score INTEGER NOT NULL, confidence_score INTEGER NOT NULL,
        primary_user VARCHAR, primary_host VARCHAR, source_ips TEXT NOT NULL DEFAULT '[]',
        affected_assets TEXT NOT NULL DEFAULT '[]', event_ids TEXT NOT NULL DEFAULT '[]',
        techniques TEXT NOT NULL DEFAULT '[]', recommended_actions TEXT NOT NULL DEFAULT '[]',
        root_cause TEXT NOT NULL, score_breakdown TEXT NOT NULL DEFAULT '{}', assigned_to VARCHAR
      );
      CREATE TABLE activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME NOT NULL, analyst VARCHAR NOT NULL,
        action VARCHAR NOT NULL, incident_id VARCHAR NOT NULL, result VARCHAR NOT NULL, details TEXT NOT NULL DEFAULT ''
      );
      INSERT INTO events VALUES ('LEGACY-1','2026-01-01','Identity','legacy@example.com',NULL,'10.0.0.1','Legacy event',0,'[]','{}');
      INSERT INTO incidents VALUES ('INC-LEGACY','Legacy incident','Preserved row','2026-01-01','2026-01-01','LOW','NEW',10,20,'legacy@example.com',NULL,'[]','[]','[\"LEGACY-1\"]','[]','[]','Legacy hypothesis','{}',NULL);
    """);connection.commit();connection.close()
    environment={**os.environ,'DATABASE_URL':f'sqlite:///{database}'}
    result=subprocess.run([sys.executable,'-m','alembic','upgrade','head'],cwd=BACKEND,env=environment,capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    connection=sqlite3.connect(database)
    event_columns={row[1] for row in connection.execute('PRAGMA table_info(events)')}
    incident_columns={row[1] for row in connection.execute('PRAGMA table_info(incidents)')}
    tables={row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert 'schema_version' in event_columns
    assert {'incident_fingerprint','confidence_breakdown','disposition','residual_risk_score'}<=incident_columns
    assert {'detection_findings','analyst_notes','evidence_bookmarks','incident_risk_history'}<=tables
    assert connection.execute("SELECT title FROM incidents WHERE id='INC-LEGACY'").fetchone()==('Legacy incident',)
    assert connection.execute("SELECT activity FROM events WHERE id='LEGACY-1'").fetchone()==('Legacy event',)
    connection.close()
