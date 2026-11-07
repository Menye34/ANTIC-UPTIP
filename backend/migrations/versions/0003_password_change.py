"""Restricted first-login password-replacement challenges; no account seeds."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('password_change_challenges',
        sa.Column('token_hash', sa.String(64), primary_key=True),
        sa.Column('user_id', pg.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('password_fingerprint', sa.String(64), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('consumed', sa.Boolean(), nullable=False),
        sa.Column('environment', sa.String(16), nullable=False))
    op.create_index('ix_password_change_challenges_user_id', 'password_change_challenges', ['user_id'])
    op.create_index('ix_password_change_challenges_expires_at', 'password_change_challenges', ['expires_at'])


def downgrade():
    op.drop_table('password_change_challenges')
