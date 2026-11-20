"""Explicit optional TCP service-discovery port boundaries; no default consent."""
from alembic import op
import sqlalchemy as sa

revision = '0025'
down_revision = '0024'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('scope_entries', sa.Column('tcp_ports', sa.ARRAY(sa.Integer()), nullable=False,
                                            server_default='{}'))
    op.create_check_constraint('ck_scope_tcp_ports', 'scope_entries',
        "cardinality(tcp_ports) <= 16 AND array_position(tcp_ports, NULL) IS NULL "
        "AND 0 < ALL(tcp_ports) AND 65536 > ALL(tcp_ports) "
        "AND (cardinality(tcp_ports) = 0 OR kind = 'IP address')")


def downgrade():
    op.execute("""LOCK TABLE assessments, scope_entries, scope_events IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM scope_entries WHERE cardinality(tcp_ports) > 0)
 OR EXISTS (SELECT 1 FROM scope_events WHERE before::jsonb ? 'tcp_ports' OR after::jsonb ? 'tcp_ports')
 THEN RAISE EXCEPTION 'Cannot erase authorized TCP port history'; END IF;
END $$;""")
    op.drop_constraint('ck_scope_tcp_ports', 'scope_entries', type_='check')
    op.drop_column('scope_entries', 'tcp_ports')
