"""Support system-managed authorization binding for Start evidence."""

from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        ALTER TABLE public.assessment_start_evidence
        ALTER COLUMN approval_reference DROP NOT NULL
    """)

    op.execute("""
        ALTER TABLE public.assessment_start_evidence
        ADD COLUMN system_authorization_reference VARCHAR(160)
    """)

    op.execute("""
        ALTER TABLE public.assessment_start_evidence
        ADD CONSTRAINT fk_start_evidence_system_authorization_binding
        FOREIGN KEY (system_authorization_reference, policy_digest)
        REFERENCES public.system_policy_authorizations
            (reference, policy_digest)
    """)

    op.execute("""
        ALTER TABLE public.assessment_start_evidence
        ADD CONSTRAINT ck_start_evidence_authorization_source
        CHECK (
            (approval_reference IS NULL)
            <> (system_authorization_reference IS NULL)
        )
    """)

    op.create_index(
        "ix_start_evidence_system_authorization",
        "assessment_start_evidence",
        ["system_authorization_reference", "policy_digest"],
    )


def downgrade():
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM public.assessment_start_evidence
                WHERE system_authorization_reference IS NOT NULL
            ) THEN
                RAISE EXCEPTION
                    'Cannot downgrade with system-managed Start evidence';
            END IF;
        END;
        $$
    """)

    op.drop_index(
        "ix_start_evidence_system_authorization",
        table_name="assessment_start_evidence",
    )

    op.drop_constraint(
        "ck_start_evidence_authorization_source",
        "assessment_start_evidence",
        type_="check",
    )

    op.drop_constraint(
        "fk_start_evidence_system_authorization_binding",
        "assessment_start_evidence",
        type_="foreignkey",
    )

    op.drop_column(
        "assessment_start_evidence",
        "system_authorization_reference",
    )

    op.execute("""
        ALTER TABLE public.assessment_start_evidence
        ALTER COLUMN approval_reference SET NOT NULL
    """)
