"""Create draft assessments, analyst assignments and creation events."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade():
    op.execute(sa.schema.CreateSequence(sa.Sequence('assessment_reference_sequence')))
    op.create_table('assessments',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True),
        sa.Column('reference', sa.String(48), nullable=False, unique=True),
        sa.Column('idempotency_key', pg.UUID(as_uuid=True), nullable=False),
        sa.Column('request_fingerprint', sa.String(64), nullable=False),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('start_date', sa.Date()),
        sa.Column('end_date', sa.Date()),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('creator_id', pg.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('lead_analyst_id', pg.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint('creator_id', 'idempotency_key', name='uq_assessments_creator_idempotency'),
        sa.CheckConstraint("status = 'Draft'", name='ck_assessments_draft'),
        sa.CheckConstraint('end_date >= start_date', name='ck_assessments_window'))
    op.create_index('ix_assessments_creator_id', 'assessments', ['creator_id'])
    op.create_table('assessment_assignments',
        sa.Column('assessment_id', pg.UUID(as_uuid=True), sa.ForeignKey('assessments.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('analyst_id', pg.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True))
    op.create_index('ix_assessment_assignments_analyst_id', 'assessment_assignments', ['analyst_id'])
    op.create_table('assessment_creation_events',
        sa.Column('assessment_id', pg.UUID(as_uuid=True), sa.ForeignKey('assessments.id'), primary_key=True),
        sa.Column('actor_id', pg.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))


def downgrade():
    op.drop_table('assessment_creation_events')
    op.drop_table('assessment_assignments')
    op.drop_table('assessments')
    op.execute(sa.schema.DropSequence(sa.Sequence('assessment_reference_sequence')))
