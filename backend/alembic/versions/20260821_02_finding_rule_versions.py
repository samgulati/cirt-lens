"""Include rule version in finding identity."""

from alembic import op

revision = "20260821_02"
down_revision = "20260820_01"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("detection_findings") as batch:
        batch.drop_constraint("uq_finding_event_rule_flag", type_="unique")
        batch.create_unique_constraint(
            "uq_finding_event_rule_version_flag", ["event_id", "rule_id", "rule_version", "flag"]
        )


def downgrade():
    with op.batch_alter_table("detection_findings") as batch:
        batch.drop_constraint("uq_finding_event_rule_version_flag", type_="unique")
        batch.create_unique_constraint(
            "uq_finding_event_rule_flag", ["event_id", "rule_id", "flag"]
        )
