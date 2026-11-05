"""Authentication foundation; no account or role seeds."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('roles', sa.Column('name', sa.String(80), primary_key=True))
    op.create_table('users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('username', sa.String(128), nullable=False, unique=True),
        sa.Column('password_hash', sa.String(512), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('role', sa.String(80), sa.ForeignKey('roles.name'), nullable=False),
        sa.Column('password_change_required', sa.Boolean(), nullable=False),
        sa.Column('mfa_required', sa.Boolean(), nullable=False),
        sa.Column('mfa_enrolled', sa.Boolean(), nullable=False),
        sa.Column('mfa_verified_at', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('active', 'disabled', 'locked')"))
    op.create_table('auth_sessions',
        sa.Column('token_hash', sa.String(64), primary_key=True),
        sa.Column('csrf_hash', sa.String(64), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False))
    op.create_index('ix_auth_sessions_user_id', 'auth_sessions', ['user_id'])
    op.create_index('ix_auth_sessions_expires_at', 'auth_sessions', ['expires_at'])
    op.create_table('login_buckets', sa.Column('key', sa.String(64), primary_key=True),
                    sa.Column('window', sa.Integer(), nullable=False), sa.Column('count', sa.Integer(), nullable=False))
    op.create_table('auth_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL')),
        sa.Column('reason', sa.String(40), nullable=False), sa.Column('client_key', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))


def downgrade():
    for name in ['auth_events', 'login_buckets', 'auth_sessions', 'users', 'roles']:
        op.drop_table(name)
