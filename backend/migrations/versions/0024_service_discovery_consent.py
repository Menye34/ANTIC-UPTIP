"""Explicit, immutable, bounded service-discovery consent; no default grants."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB
revision = '0024'
down_revision = '0023'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('service_discovery_consents',
        sa.Column('request_id', UUID(as_uuid=True), primary_key=True),
        sa.Column('assessment_id', UUID(as_uuid=True), nullable=False),
        sa.Column('target_id', UUID(as_uuid=True), nullable=False),
        sa.Column('actor_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('idempotency_key', UUID(as_uuid=True), nullable=False),
        sa.Column('snapshot', JSONB(), nullable=False),
        sa.Column('digest', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['request_id', 'assessment_id', 'target_id'],
            ['baseline_execution_requests.id', 'baseline_execution_requests.assessment_id',
             'baseline_execution_requests.target_id'], name='fk_service_consent_request'),
        sa.UniqueConstraint('assessment_id', 'idempotency_key', name='uq_service_consent_key'),
        sa.CheckConstraint("expires_at > created_at AND expires_at <= created_at + interval '1 hour'", name='ck_service_consent_expiry'),
        sa.CheckConstraint("digest ~ '^[0-9a-f]{64}$' AND jsonb_typeof(snapshot)='object'", name='ck_service_consent_snapshot'))
    op.create_table('service_discovery_revocations',
        sa.Column('request_id', UUID(as_uuid=True), sa.ForeignKey('service_discovery_consents.request_id'), primary_key=True),
        sa.Column('actor_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    for table in ('service_discovery_consents', 'service_discovery_revocations'):
        op.execute(f'''CREATE TRIGGER immutable_{table} BEFORE UPDATE OR DELETE ON {table}
FOR EACH ROW EXECUTE FUNCTION reject_execution_history_change();
CREATE TRIGGER no_truncate_{table} BEFORE TRUNCATE ON {table}
FOR EACH STATEMENT EXECUTE FUNCTION reject_execution_history_change();
GRANT SELECT, INSERT ON {table} TO uptip_runtime;''')
    # Every consent/revocation writer coordinates with worker and completion's
    # assessment lock, including direct INSERTs by the runtime database role.
    op.execute('''CREATE FUNCTION lock_service_consent_assessment() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE aid uuid; creator uuid; lifecycle text;
BEGIN
 IF TG_TABLE_NAME='service_discovery_consents' THEN aid:=NEW.assessment_id;
 ELSE SELECT assessment_id INTO aid FROM public.service_discovery_consents WHERE request_id=NEW.request_id; END IF;
 SELECT creator_id INTO creator FROM public.assessments WHERE id=aid;
 PERFORM id FROM public.users WHERE id=creator FOR UPDATE;
 SELECT status INTO lifecycle FROM public.assessments WHERE id=aid FOR UPDATE;
 IF lifecycle IS DISTINCT FROM 'Testing' OR creator IS DISTINCT FROM NEW.actor_id
 THEN RAISE EXCEPTION 'Service consent requires Testing creator'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION lock_service_consent_assessment() FROM PUBLIC;
CREATE TRIGGER lock_service_consent BEFORE INSERT ON service_discovery_consents
FOR EACH ROW EXECUTE FUNCTION lock_service_consent_assessment();
CREATE TRIGGER lock_service_revocation BEFORE INSERT ON service_discovery_revocations
FOR EACH ROW EXECUTE FUNCTION lock_service_consent_assessment();''')

    op.execute("""CREATE FUNCTION validate_service_observation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE profile text; parameters jsonb;
BEGIN
 SELECT profile_id, a.parameters INTO profile, parameters FROM public.execution_attempts a WHERE id=NEW.attempt_id;
 IF profile IS DISTINCT FROM 'service-discovery' THEN RETURN NEW; END IF;
 IF NEW.observation_type IS DISTINCT FROM 'service_discovery'
 OR (NEW.data - ARRAY['address','port','state','transport','service','version']) <> '{}'::jsonb
 OR NEW.data->>'address' IS DISTINCT FROM parameters->>'target'
 OR NEW.data->>'state' IS DISTINCT FROM 'open'
 OR NEW.data->>'transport' IS DISTINCT FROM 'tcp'
 OR jsonb_typeof(NEW.data->'service') IS DISTINCT FROM 'string'
 OR coalesce(NEW.data->>'service','') !~ '^[a-z0-9][a-z0-9_.+-]{0,79}$'
 OR jsonb_typeof(NEW.data->'port') IS DISTINCT FROM 'number'
 OR coalesce(NEW.data->>'port','') !~ '^[0-9]{1,5}$'
 THEN RAISE EXCEPTION 'Invalid normalized service observation'; END IF;
 IF (NEW.data->>'port')::integer NOT BETWEEN 1 AND 65535
 OR NOT (parameters->'ports' @> jsonb_build_array((NEW.data->>'port')::integer))
 OR (NEW.data ? 'version' AND (jsonb_typeof(NEW.data->'version') <> 'string'
     OR length(NEW.data->>'version') > 120 OR NEW.data->>'version' ~ '[[:cntrl:]]'))
 THEN RAISE EXCEPTION 'Service observation exceeds authorized plan'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION validate_service_observation() FROM PUBLIC;
CREATE TRIGGER validate_service_observation BEFORE INSERT ON security_observations
FOR EACH ROW EXECUTE FUNCTION validate_service_observation();""")


def downgrade():
    op.execute('''LOCK TABLE assessments, service_discovery_consents, service_discovery_revocations IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN IF EXISTS (SELECT 1 FROM service_discovery_consents)
OR EXISTS (SELECT 1 FROM baseline_execution_requests WHERE profile_id='service-discovery')
THEN RAISE EXCEPTION 'Cannot erase service discovery consent history'; END IF; END $$;''')
    op.execute('DROP TRIGGER validate_service_observation ON security_observations')
    op.execute('DROP FUNCTION validate_service_observation()')
    op.drop_table('service_discovery_revocations')
    op.drop_table('service_discovery_consents')
    op.execute('DROP FUNCTION lock_service_consent_assessment()')
