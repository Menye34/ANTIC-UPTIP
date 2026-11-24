"""Persist validated finding AI interactions."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "finding_ai_history",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column(
            "assessment_id", sa.UUID(),
            sa.ForeignKey("assessments.id"),
            nullable=False,
        ),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column(
            "actor_id", sa.UUID(),
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("question", sa.String(500), nullable=False),
        sa.Column("answer", sa.Text(), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column(
            "prompt_version", sa.String(80), nullable=False
        ),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.Column("evidence", JSONB(), nullable=False),
        sa.Column("limitations", JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "assessment_id"],
            [
                "consolidated_findings.id",
                "consolidated_findings.assessment_id",
            ],
            name="fk_ai_history_finding_assessment",
        ),
        sa.CheckConstraint(
            "action IN ('explain_finding', 'explain_impact', "
            "'suggest_fix', 'write_description', "
            "'explain_tool_output', 'custom')",
            name="ck_ai_history_action",
        ),
        sa.CheckConstraint(
            "char_length(question) BETWEEN 1 AND 500 "
            "AND btrim(question) <> ''",
            name="ck_ai_history_question",
        ),
        sa.CheckConstraint(
            "char_length(answer) BETWEEN 1 AND 6000 "
            "AND btrim(answer) <> ''",
            name="ck_ai_history_answer",
        ),
        sa.CheckConstraint(
            "output_tokens BETWEEN 1 AND 512",
            name="ck_ai_history_output_tokens",
        ),
        sa.CheckConstraint(
            "CASE WHEN jsonb_typeof(evidence) = 'array' "
            "THEN jsonb_array_length(evidence) BETWEEN 1 AND 3 "
            "ELSE false END",
            name="ck_ai_history_evidence",
        ),
        sa.CheckConstraint(
            "CASE WHEN jsonb_typeof(limitations) = 'array' "
            "THEN jsonb_array_length(limitations) <= 8 "
            "ELSE false END",
            name="ck_ai_history_limitations",
        ),
    )

    op.create_index(
        "ix_ai_history_scope_created",
        "finding_ai_history",
        [
            "assessment_id",
            "finding_id",
            "actor_id",
            "created_at",
            "id",
        ],
    )

    op.execute("""
        REVOKE ALL ON public.finding_ai_history FROM PUBLIC;
        REVOKE ALL ON public.finding_ai_history FROM uptip_runtime;
        GRANT SELECT, INSERT
        ON public.finding_ai_history TO uptip_runtime;
    """)


def downgrade():
    raise RuntimeError(
        "Automatic downgrade disabled to preserve AI history."
    )
