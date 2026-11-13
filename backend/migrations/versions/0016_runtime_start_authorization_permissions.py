"""Grant least-privilege runtime access for Assessment Start history."""

from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        GRANT SELECT, INSERT
        ON TABLE public.assessment_start_authorizations
        TO uptip_runtime
    """)

    op.execute("""
        GRANT INSERT
        ON TABLE public.assessment_start_events
        TO uptip_runtime
    """)


def downgrade():
    op.execute("""
        REVOKE INSERT
        ON TABLE public.assessment_start_events
        FROM uptip_runtime
    """)

    op.execute("""
        REVOKE SELECT, INSERT
        ON TABLE public.assessment_start_authorizations
        FROM uptip_runtime
    """)
