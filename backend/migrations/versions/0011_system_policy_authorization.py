"""Add append-only system-managed policy authorization records."""

from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

_TABLES = (
    "system_policy_authorizations",
    "system_policy_authorization_revocations",
)


def upgrade():
    op.execute("""
        CREATE TABLE system_policy_authorizations (
            reference VARCHAR(160) PRIMARY KEY,
            policy_digest VARCHAR(64) NOT NULL
                REFERENCES execution_policy_versions(digest),
            provenance TEXT NOT NULL,
            valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
            valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
            recorded_at TIMESTAMP WITH TIME ZONE
                DEFAULT now() NOT NULL,
            CONSTRAINT uq_system_authorization_binding
                UNIQUE (reference, policy_digest),
            CONSTRAINT ck_system_authorization_window
                CHECK (valid_until > valid_from),
            CONSTRAINT ck_system_authorization_identity
                CHECK (
                    btrim(reference) <> ''
                    AND btrim(provenance) <> ''
                )
        )
    """)

    op.execute("""
        CREATE TABLE system_policy_authorization_revocations (
            id UUID PRIMARY KEY,
            authorization_reference VARCHAR(160) NOT NULL
                UNIQUE REFERENCES system_policy_authorizations(reference),
            reason TEXT NOT NULL,
            provenance TEXT NOT NULL,
            recorded_at TIMESTAMP WITH TIME ZONE
                DEFAULT now() NOT NULL,
            CONSTRAINT ck_system_authorization_revocation_identity
                CHECK (
                    btrim(reason) <> ''
                    AND btrim(provenance) <> ''
                )
        )
    """)

    for table in _TABLES:
        op.execute(f"""
            CREATE TRIGGER reject_governed_authorization_change
            BEFORE UPDATE OR DELETE OR TRUNCATE ON {table}
            FOR EACH STATEMENT
            EXECUTE FUNCTION reject_governed_authorization_change()
        """)


def downgrade():
    op.execute(
        "LOCK TABLE " + ", ".join(_TABLES) + " IN ACCESS EXCLUSIVE MODE"
    )

    for table in _TABLES:
        op.execute(f"""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM {table}) THEN
                    RAISE EXCEPTION
                        'Cannot downgrade with system authorization history';
                END IF;
            END;
            $$
        """)

    for table in reversed(_TABLES):
        op.drop_table(table)
