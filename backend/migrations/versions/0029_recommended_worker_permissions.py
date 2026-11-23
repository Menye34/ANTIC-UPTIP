"""Grant the dedicated execution worker append-only normalization access."""

from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_roles
                WHERE rolname = 'uptip_worker'
            ) THEN
                GRANT SELECT, INSERT
                ON TABLE public.recommended_processing_outcomes,
                         public.recommended_observations
                TO uptip_worker;
            END IF;
        END $$;
    """)


def downgrade():
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_roles
                WHERE rolname = 'uptip_worker'
            ) THEN
                REVOKE SELECT, INSERT
                ON TABLE public.recommended_processing_outcomes,
                         public.recommended_observations
                FROM uptip_worker;
            END IF;
        END $$;
    """)
