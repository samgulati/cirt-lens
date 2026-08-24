"""Make detection-rule versions tenant-owned.

Revision ID: 20260824_04
Revises: 20260822_03
"""

from alembic import op
import sqlalchemy as sa

revision = "20260824_04"
down_revision = "20260822_03"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("detection_rules") as batch:
        batch.drop_constraint("uq_rule_version", type_="unique")
        batch.drop_index("ix_rule_status")
        batch.add_column(
            sa.Column("tenant_id", sa.String(), nullable=False, server_default="tenant-demo")
        )
        batch.create_index("ix_detection_rules_tenant_id", ["tenant_id"])
        batch.create_index("ix_rule_tenant_status", ["tenant_id", "status"])
        batch.create_unique_constraint("uq_rule_version", ["tenant_id", "rule_id", "version"])


def downgrade():
    with op.batch_alter_table("detection_rules") as batch:
        batch.drop_constraint("uq_rule_version", type_="unique")
        batch.drop_index("ix_rule_tenant_status")
        batch.drop_index("ix_detection_rules_tenant_id")
        batch.drop_column("tenant_id")
        batch.create_index("ix_rule_status", ["status"])
        batch.create_unique_constraint("uq_rule_version", ["rule_id", "version"])
