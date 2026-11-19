"""Testing completion lifecycle, recommendation decisions and audit receipts."""
from alembic import op
import sqlalchemy as sa

revision = '0021'
down_revision = '0020'
branch_labels = None
depends_on = None

def upgrade():
    op.drop_constraint('ck_assessments_start_state', 'assessments', type_='check')
    op.create_check_constraint('ck_assessments_start_state', 'assessments',
        "status IN ('Draft', 'Ready', 'Testing', 'Finding Review')")
    op.create_table('testing_recommendation_decisions',
        sa.Column('assessment_id', sa.Uuid(), sa.ForeignKey('assessments.id'), primary_key=True),
        sa.Column('recommendation_id', sa.String(64), primary_key=True),
        sa.Column('actor_id', sa.Uuid(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('decision', sa.String(16), nullable=False),
        sa.Column('decided_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("decision IN ('Reviewed', 'Deferred')", name='ck_testing_recommendation_decision'))
    op.create_table('testing_completion_events',
        sa.Column('assessment_id', sa.Uuid(), sa.ForeignKey('assessments.id'), primary_key=True),
        sa.Column('actor_id', sa.Uuid(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('snapshot', sa.JSON(), nullable=False))

    # Runtime access is scoped to review decisions and immutable completion receipts.
    # No execution authorization or scanner dispatch privileges are granted.
    op.execute("GRANT SELECT, INSERT, UPDATE ON public.testing_recommendation_decisions TO uptip_runtime")
    op.execute("GRANT SELECT, INSERT ON public.testing_completion_events TO uptip_runtime")

def downgrade():
    op.execute("REVOKE SELECT, INSERT, UPDATE ON public.testing_recommendation_decisions FROM uptip_runtime")
    op.execute("REVOKE SELECT, INSERT ON public.testing_completion_events FROM uptip_runtime")
    op.execute("UPDATE assessments SET status = 'Testing' WHERE status = 'Finding Review'")
    op.drop_table('testing_completion_events')
    op.drop_table('testing_recommendation_decisions')
    op.drop_constraint('ck_assessments_start_state', 'assessments', type_='check')
    op.create_check_constraint('ck_assessments_start_state', 'assessments',
        "status IN ('Draft', 'Ready', 'Testing')")
