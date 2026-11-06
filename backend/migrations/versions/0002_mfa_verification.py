"""Encrypted MFA credentials, purpose-bound pending challenges, session proof."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('mfa_credentials',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', pg.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('secret_ciphertext', sa.String(512), nullable=False),
        sa.Column('last_accepted_step', sa.BigInteger()),
        sa.Column('failed_attempts', sa.Integer(), nullable=False),
        sa.Column('locked_until', sa.DateTime(timezone=True)))
    op.create_table('mfa_challenges',
        sa.Column('token_hash', sa.String(64), primary_key=True),
        sa.Column('user_id', pg.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('credential_id', pg.UUID(as_uuid=True), sa.ForeignKey('mfa_credentials.id', ondelete='CASCADE'), nullable=False),
        sa.Column('password_fingerprint', sa.String(64), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('consumed', sa.Boolean(), nullable=False),
        sa.Column('environment', sa.String(16), nullable=False))
    op.create_index('ix_mfa_challenges_user_id', 'mfa_challenges', ['user_id'])
    op.create_index('ix_mfa_challenges_expires_at', 'mfa_challenges', ['expires_at'])
    op.add_column('auth_sessions', sa.Column('mfa_credential_id', pg.UUID(as_uuid=True)))
    op.create_foreign_key('fk_session_mfa_credential', 'auth_sessions', 'mfa_credentials',
                          ['mfa_credential_id'], ['id'], ondelete='SET NULL')


def downgrade():
    op.drop_constraint('fk_session_mfa_credential', 'auth_sessions', type_='foreignkey')
    op.drop_column('auth_sessions', 'mfa_credential_id')
    op.drop_table('mfa_challenges')
    op.drop_table('mfa_credentials')
