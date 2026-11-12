"""Permit least-privilege runtime Start confirmation."""

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        GRANT SELECT, INSERT
        ON TABLE public.baseline_execution_requests
        TO uptip_runtime
    """)

    op.execute("""
        CREATE FUNCTION public.lock_assessment_start_sources()
        RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        BEGIN
            LOCK TABLE
                public.baseline_tool_states,
                public.execution_policy_versions,
                public.execution_policy_approvals,
                public.assessment_start_evidence,
                public.authorization_record_revocations,
                public.system_policy_authorizations,
                public.system_policy_authorization_revocations
            IN SHARE MODE;
        END;
        $$
    """)

    op.execute("""
        REVOKE ALL ON FUNCTION
        public.lock_assessment_start_sources()
        FROM PUBLIC
    """)

    op.execute("""
        GRANT EXECUTE ON FUNCTION
        public.lock_assessment_start_sources()
        TO uptip_runtime
    """)


def downgrade():
    op.execute("""
        REVOKE EXECUTE ON FUNCTION
        public.lock_assessment_start_sources()
        FROM uptip_runtime
    """)

    op.execute("""
        DROP FUNCTION public.lock_assessment_start_sources()
    """)

    op.execute("""
        REVOKE SELECT, INSERT
        ON TABLE public.baseline_execution_requests
        FROM uptip_runtime
    """)
