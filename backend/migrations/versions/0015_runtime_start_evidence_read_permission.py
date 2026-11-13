"""Grant runtime read access to trusted Start evidence."""

from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        GRANT SELECT
        ON TABLE public.assessment_start_evidence
        TO uptip_runtime
    """)


def downgrade():
    op.execute("""
        REVOKE SELECT
        ON TABLE public.assessment_start_evidence
        FROM uptip_runtime
    """)
