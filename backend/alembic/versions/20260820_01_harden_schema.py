"""Add versioned findings, incident identity, and case-management audit data."""
from alembic import op
import sqlalchemy as sa

revision="20260820_01"
down_revision=None
branch_labels=None
depends_on=None

def upgrade():
    bind=op.get_bind()
    # Alembic owns schema evolution. Fresh test/demo databases should be created
    # from the explicit revision chain, never current ORM metadata.
    tables=set(sa.inspect(bind).get_table_names())
    if "events" not in tables:
        op.create_table("events",sa.Column("id",sa.String(),primary_key=True),sa.Column("timestamp",sa.DateTime(),nullable=False),sa.Column("source",sa.String(),nullable=False),sa.Column("user",sa.String()),sa.Column("host",sa.String()),sa.Column("source_ip",sa.String()),sa.Column("activity",sa.String(),nullable=False),sa.Column("risk_score",sa.Integer(),nullable=False,server_default="0"),sa.Column("risk_flags",sa.Text(),nullable=False,server_default="[]"),sa.Column("data",sa.Text(),nullable=False,server_default="{}"),sa.Column("schema_version",sa.String(),nullable=False,server_default="1.0"))
    if "incidents" not in tables:
        op.create_table("incidents",sa.Column("id",sa.String(),primary_key=True),sa.Column("title",sa.String(),nullable=False),sa.Column("description",sa.Text(),nullable=False),sa.Column("created_at",sa.DateTime(),nullable=False),sa.Column("updated_at",sa.DateTime(),nullable=False),sa.Column("severity",sa.String(),nullable=False),sa.Column("status",sa.String(),nullable=False,server_default="NEW"),sa.Column("risk_score",sa.Integer(),nullable=False),sa.Column("confidence_score",sa.Integer(),nullable=False),sa.Column("primary_user",sa.String()),sa.Column("primary_host",sa.String()),sa.Column("source_ips",sa.Text(),nullable=False,server_default="[]"),sa.Column("affected_assets",sa.Text(),nullable=False,server_default="[]"),sa.Column("event_ids",sa.Text(),nullable=False,server_default="[]"),sa.Column("techniques",sa.Text(),nullable=False,server_default="[]"),sa.Column("recommended_actions",sa.Text(),nullable=False,server_default="[]"),sa.Column("root_cause",sa.Text(),nullable=False),sa.Column("score_breakdown",sa.Text(),nullable=False,server_default="{}"),sa.Column("assigned_to",sa.String()),sa.Column("incident_type",sa.String(),nullable=False,server_default="Security Incident"),sa.Column("residual_risk_score",sa.Integer(),nullable=False,server_default="0"),sa.Column("triaged_at",sa.DateTime()),sa.Column("incident_fingerprint",sa.String()),sa.Column("confidence_breakdown",sa.Text(),nullable=False,server_default="{}"),sa.Column("disposition",sa.String(),nullable=False,server_default="UNSET"))
        op.create_index("ix_incidents_incident_fingerprint","incidents",["incident_fingerprint"],unique=True)
    definitions={"activity":[sa.Column("id",sa.Integer(),primary_key=True),sa.Column("timestamp",sa.DateTime(),nullable=False),sa.Column("analyst",sa.String(),nullable=False),sa.Column("action",sa.String(),nullable=False),sa.Column("incident_id",sa.String(),nullable=False),sa.Column("result",sa.String(),nullable=False),sa.Column("details",sa.Text(),nullable=False,server_default="")],"detection_findings":[sa.Column("id",sa.Integer(),primary_key=True),sa.Column("event_id",sa.String(),nullable=False),sa.Column("rule_id",sa.String(),nullable=False),sa.Column("rule_version",sa.String(),nullable=False),sa.Column("flag",sa.String(),nullable=False),sa.Column("risk_contribution",sa.Integer(),nullable=False),sa.Column("reason",sa.Text(),nullable=False),sa.Column("metadata_json",sa.Text(),nullable=False,server_default="{}"),sa.Column("created_at",sa.DateTime(),nullable=False),sa.UniqueConstraint("event_id","rule_id","flag",name="uq_finding_event_rule_flag")],"analyst_notes":[sa.Column("id",sa.Integer(),primary_key=True),sa.Column("incident_id",sa.String(),nullable=False),sa.Column("analyst",sa.String(),nullable=False),sa.Column("text",sa.Text(),nullable=False),sa.Column("timestamp",sa.DateTime(),nullable=False)],"evidence_bookmarks":[sa.Column("id",sa.Integer(),primary_key=True),sa.Column("incident_id",sa.String(),nullable=False),sa.Column("event_id",sa.String(),nullable=False),sa.Column("analyst",sa.String(),nullable=False),sa.Column("note",sa.Text(),nullable=False,server_default=""),sa.Column("timestamp",sa.DateTime(),nullable=False),sa.UniqueConstraint("incident_id","event_id",name="uq_bookmark_incident_event")],"incident_risk_history":[sa.Column("id",sa.Integer(),primary_key=True),sa.Column("incident_id",sa.String(),nullable=False),sa.Column("timestamp",sa.DateTime(),nullable=False),sa.Column("original_risk",sa.Integer(),nullable=False),sa.Column("residual_risk",sa.Integer(),nullable=False),sa.Column("reason",sa.String(),nullable=False),sa.Column("activity_id",sa.Integer())]}
    for name,columns in definitions.items():
        if name not in tables:op.create_table(name,*columns)
    inspector=sa.inspect(bind)
    if "events" in inspector.get_table_names():
        columns={c["name"] for c in inspector.get_columns("events")}
        if "schema_version" not in columns:
            with op.batch_alter_table("events") as batch:batch.add_column(sa.Column("schema_version",sa.String(),nullable=False,server_default="1.0"))
    if "incidents" in inspector.get_table_names():
        columns={c["name"] for c in inspector.get_columns("incidents")}
        additions=[("incident_type",sa.String(),"Security Incident"),("residual_risk_score",sa.Integer(),"0"),("triaged_at",sa.DateTime(),None),("incident_fingerprint",sa.String(),None),("confidence_breakdown",sa.Text(),"{}"),("disposition",sa.String(),"UNSET")]
        for name,type_,default in additions:
            if name not in columns:
                with op.batch_alter_table("incidents") as batch:batch.add_column(sa.Column(name,type_,nullable=True if default is None else False,server_default=default))
        indexes={i["name"] for i in sa.inspect(bind).get_indexes("incidents")}
        if "ix_incidents_incident_fingerprint" not in indexes:
            op.create_index("ix_incidents_incident_fingerprint","incidents",["incident_fingerprint"],unique=True)

def downgrade():
    # Portfolio demo data is intentionally preserved; use a new SQLite volume
    # for a clean downgrade rather than destructively dropping case records.
    pass
