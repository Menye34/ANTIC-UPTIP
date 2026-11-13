"""Persist initial assessment Start authorization and its lifecycle event."""
from alembic import op
import sqlalchemy as sa

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint('ck_assessments_draft', 'assessments', type_='check')
    op.create_check_constraint('ck_assessments_start_state', 'assessments', "status IN ('Draft', 'Ready')")
    op.create_table(
        'assessment_start_authorizations',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('assessment_id', sa.Uuid(), sa.ForeignKey('assessments.id'), nullable=False, unique=True),
        sa.Column('actor_id', sa.Uuid(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('idempotency_key', sa.Uuid(), nullable=False),
        sa.Column('request_fingerprint', sa.String(64), nullable=False),
        sa.Column('mode', sa.String(7), nullable=False),
        sa.Column('snapshot_version', sa.Integer(), nullable=False),
        sa.Column('snapshot_digest', sa.String(64), nullable=False),
        sa.Column('snapshot', sa.JSON(), nullable=False),
        sa.Column('confirmed_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('assessment_id', 'actor_id', 'idempotency_key', name='uq_start_actor_key'),
        sa.CheckConstraint("mode IN ('full', 'partial')", name='ck_start_mode'),
        sa.CheckConstraint('snapshot_version > 0', name='ck_start_snapshot_version'),
    )
    op.create_table(
        'assessment_start_events',
        sa.Column('authorization_id', sa.Uuid(), sa.ForeignKey('assessment_start_authorizations.id'), primary_key=True),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('from_status', sa.String(16), nullable=False),
        sa.Column('to_status', sa.String(16), nullable=False),
    )
    op.execute("""
        CREATE FUNCTION reject_assessment_start_change() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Assessment Start history is append-only';
        END;
        $$
    """)
    for table in ('assessment_start_authorizations', 'assessment_start_events'):
        op.execute(f"""
            CREATE TRIGGER reject_start_change BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION reject_assessment_start_change()
        """)


def downgrade():
    op.execute('LOCK TABLE assessments, assessment_start_authorizations, assessment_start_events IN ACCESS EXCLUSIVE MODE')
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM assessment_start_authorizations)
                OR EXISTS (SELECT 1 FROM assessment_start_events)
                OR EXISTS (SELECT 1 FROM assessments WHERE status IN ('Ready', 'Testing')) THEN
                RAISE EXCEPTION 'Cannot downgrade while assessment Start history or Ready assessments exist';
            END IF;
        END;
        $$
    """)
    op.drop_table('assessment_start_events')
    op.drop_table('assessment_start_authorizations')
    op.execute('DROP FUNCTION reject_assessment_start_change()')
    op.drop_constraint('ck_assessments_start_state', 'assessments', type_='check')
    op.create_check_constraint('ck_assessments_draft', 'assessments', "status = 'Draft'")
