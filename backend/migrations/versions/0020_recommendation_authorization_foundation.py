"""Separate, non-dispatchable recommendation authorization and request records."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSON

revision = '0020'
down_revision = '0019'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('recommendation_authorization_records',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('assessment_id', UUID(as_uuid=True), sa.ForeignKey('assessments.id'), nullable=False),
        sa.Column('target_id', UUID(as_uuid=True), nullable=False),
        sa.Column('actor_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('recommendation_id', sa.String(64), nullable=False),
        sa.Column('source_observation_id', UUID(as_uuid=True), nullable=False),
        sa.Column('source_evidence_id', UUID(as_uuid=True), nullable=False),
        sa.Column('profile_id', sa.String(80), nullable=False),
        sa.Column('profile_version', sa.Integer(), nullable=False),
        sa.Column('scope_revision', sa.Integer(), nullable=False),
        sa.Column('authorization_snapshot', JSON(), nullable=False),
        sa.Column('snapshot_digest', sa.String(64), nullable=False),
        sa.Column('idempotency_key', sa.String(160), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('id', 'assessment_id', 'target_id', name='uq_rec_auth_binding'),
        sa.UniqueConstraint('assessment_id', 'actor_id', 'idempotency_key', name='uq_rec_auth_actor_key'),
        sa.ForeignKeyConstraint(['target_id', 'assessment_id'],
                                ['assessment_targets.id', 'assessment_targets.assessment_id'],
                                name='fk_rec_auth_target_assessment'),
        sa.CheckConstraint("status IN ('Pending', 'Denied', 'Approved', 'Revoked')", name='ck_rec_auth_status'),
        sa.CheckConstraint('length(recommendation_id) = 64', name='ck_rec_auth_rec_id'))
    op.create_index('ix_rec_auth_assessment_created', 'recommendation_authorization_records',
                    ['assessment_id', 'created_at'])
    op.create_table('recommendation_execution_requests',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('assessment_id', UUID(as_uuid=True), nullable=False),
        sa.Column('target_id', UUID(as_uuid=True), nullable=False),
        sa.Column('authorization_id', UUID(as_uuid=True), nullable=False),
        sa.Column('status', sa.String(32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('authorization_id', name='uq_rec_execution_auth'),
        sa.ForeignKeyConstraint(['authorization_id', 'assessment_id', 'target_id'],
                                ['recommendation_authorization_records.id',
                                 'recommendation_authorization_records.assessment_id',
                                 'recommendation_authorization_records.target_id'],
                                name='fk_rec_execution_auth_binding'),
        sa.CheckConstraint("status IN ('PendingVerification', 'Blocked', 'Cancelled')",
                           name='ck_rec_execution_non_dispatchable'))
    op.create_index('ix_rec_execution_assessment', 'recommendation_execution_requests',
                    ['assessment_id', 'created_at'])
    # No runtime INSERT/UPDATE/DELETE grants or worker dispatch route are added.


def downgrade():
    op.drop_index('ix_rec_execution_assessment', table_name='recommendation_execution_requests')
    op.drop_table('recommendation_execution_requests')
    op.drop_index('ix_rec_auth_assessment_created', table_name='recommendation_authorization_records')
    op.drop_table('recommendation_authorization_records')
