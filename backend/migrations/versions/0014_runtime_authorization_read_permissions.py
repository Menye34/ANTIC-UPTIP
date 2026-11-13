"""Grant runtime read access to trusted authorization records."""

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


AUTHORIZATION_TABLES = (
    "execution_policy_versions",
    "execution_policy_approvals",
    "authorization_record_revocations",
    "system_policy_authorizations",
    "system_policy_authorization_revocations",
)


def upgrade():
    for table in AUTHORIZATION_TABLES:
        op.execute(
            f"GRANT SELECT ON TABLE public.{table} TO uptip_runtime"
        )


def downgrade():
    for table in AUTHORIZATION_TABLES:
        op.execute(
            f"REVOKE SELECT ON TABLE public.{table} FROM uptip_runtime"
        )
