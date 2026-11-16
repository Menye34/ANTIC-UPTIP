"""Automatic execution persistence only; no dispatch or scanner operations."""
from alembic import op

revision = '0018'
down_revision = '0017'
branch_labels = None
depends_on = None


def upgrade():
    op.create_unique_constraint('uq_execution_request_binding', 'baseline_execution_requests', ['id','assessment_id','target_id'])
    op.execute("""
CREATE TABLE execution_attempts (
	id UUID NOT NULL,
	request_id UUID NOT NULL,
	assessment_id UUID NOT NULL,
	target_id UUID NOT NULL,
	attempt_number INTEGER NOT NULL,
	claim_id UUID NOT NULL,
	worker_id VARCHAR(160) NOT NULL,
	claimed_at TIMESTAMP WITH TIME ZONE NOT NULL,
	heartbeat_at TIMESTAMP WITH TIME ZONE NOT NULL,
	lease_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	started_at TIMESTAMP WITH TIME ZONE,
	finished_at TIMESTAMP WITH TIME ZONE,
	status VARCHAR(24) NOT NULL,
	reason_code VARCHAR(80),
	exit_code INTEGER,
	tool VARCHAR(80) NOT NULL,
	profile_id VARCHAR(80) NOT NULL,
	profile_version INTEGER NOT NULL,
	parameters JSONB NOT NULL,
	parameter_digest VARCHAR(64) NOT NULL,
	timeout_seconds INTEGER NOT NULL,
	process_reference VARCHAR(160),
	recovery_reason VARCHAR(80),
	cancellation_requested_at TIMESTAMP WITH TIME ZONE,
	cancellation_actor_id UUID,
	cancellation_source VARCHAR(16),
	cancellation_reason VARCHAR(80),
	terminated_at TIMESTAMP WITH TIME ZONE,
	termination_outcome VARCHAR(80),
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT fk_attempt_request_binding FOREIGN KEY(request_id, assessment_id, target_id) REFERENCES baseline_execution_requests (id, assessment_id, target_id),
	CONSTRAINT uq_attempt_binding UNIQUE (id, request_id, assessment_id, target_id),
	CONSTRAINT uq_attempt_number UNIQUE (request_id, attempt_number),
	CONSTRAINT ck_attempt_positive CHECK (attempt_number > 0 AND profile_version > 0 AND timeout_seconds > 0),
	CONSTRAINT ck_attempt_status CHECK (status IN ('Claimed','Running','RecoveryRequired','Succeeded','Failed','Stopped','Blocked','Cancelled')),
	CONSTRAINT ck_attempt_parameters CHECK (parameter_digest ~ '^[0-9a-f]{64}$' AND jsonb_typeof(parameters)='object' AND octet_length(parameters::text)<=65536),
	CONSTRAINT ck_attempt_identity CHECK (btrim(worker_id)<>'' AND btrim(profile_id)<>'' AND btrim(tool)<>''),
	CONSTRAINT ck_attempt_lease CHECK (lease_expires_at > claimed_at AND heartbeat_at >= claimed_at),
	CONSTRAINT ck_attempt_start CHECK (started_at IS NULL OR started_at >= claimed_at),
	CONSTRAINT ck_attempt_finish CHECK (finished_at IS NULL OR finished_at >= coalesce(started_at,claimed_at)),
	CONSTRAINT ck_attempt_termination CHECK (terminated_at IS NULL OR (started_at IS NOT NULL AND terminated_at >= started_at)),
	CONSTRAINT ck_attempt_terminal CHECK ((status IN ('Claimed','Running','RecoveryRequired') AND finished_at IS NULL) OR (status IN ('Succeeded','Failed','Stopped','Blocked','Cancelled') AND finished_at IS NOT NULL AND (started_at IS NULL OR terminated_at IS NOT NULL))),
	CONSTRAINT ck_attempt_running CHECK (status NOT IN ('Running','Succeeded') OR started_at IS NOT NULL),
	CONSTRAINT ck_attempt_success CHECK (status<>'Succeeded' OR (exit_code IS NOT NULL AND exit_code=0)),
	CONSTRAINT ck_attempt_reason CHECK (status='Claimed' OR (reason_code IS NOT NULL AND btrim(reason_code)<>'')),
	CONSTRAINT ck_attempt_cancellation CHECK (cancellation_requested_at IS NULL OR (cancellation_source IS NOT NULL AND cancellation_source IN ('analyst','system') AND cancellation_reason IS NOT NULL AND btrim(cancellation_reason)<>'' AND (cancellation_source<>'analyst' OR cancellation_actor_id IS NOT NULL))),
	UNIQUE (claim_id),
	FOREIGN KEY(cancellation_actor_id) REFERENCES users (id)
)

""")
    op.execute('CREATE INDEX ix_attempt_recovery ON execution_attempts (status, lease_expires_at)')
    op.execute("CREATE UNIQUE INDEX uq_attempt_active ON execution_attempts (request_id) WHERE status IN ('Claimed','Running','RecoveryRequired')")
    op.execute("""
CREATE TABLE scanner_evidence (
	id UUID NOT NULL,
	attempt_id UUID NOT NULL,
	request_id UUID NOT NULL,
	assessment_id UUID NOT NULL,
	target_id UUID NOT NULL,
	tool VARCHAR(80) NOT NULL,
	format VARCHAR(32) NOT NULL,
	content BYTEA,
	storage_key VARCHAR(512),
	content_hash VARCHAR(64) NOT NULL,
	size_bytes INTEGER NOT NULL,
	is_partial BOOLEAN NOT NULL,
	collected_at TIMESTAMP WITH TIME ZONE NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT fk_evidence_attempt_binding FOREIGN KEY(attempt_id, request_id, assessment_id, target_id) REFERENCES execution_attempts (id, request_id, assessment_id, target_id),
	CONSTRAINT uq_evidence_binding UNIQUE (id, attempt_id, request_id, assessment_id, target_id),
	CONSTRAINT uq_evidence_content UNIQUE (attempt_id, format, content_hash, is_partial),
	CONSTRAINT ck_evidence_identity CHECK (content_hash ~ '^[0-9a-f]{64}$' AND btrim(tool)<>'' AND btrim(format)<>''),
	CONSTRAINT ck_evidence_storage CHECK ((content IS NULL) <> (storage_key IS NULL)),
	CONSTRAINT ck_evidence_size CHECK (size_bytes >= 0 AND size_bytes <= 67108864),
	CONSTRAINT ck_evidence_inline_integrity CHECK (content IS NULL OR (octet_length(content)<=1048576 AND octet_length(content)=size_bytes AND encode(sha256(content),'hex')=content_hash)),
	CONSTRAINT ck_evidence_storage_key CHECK (storage_key IS NULL OR (storage_key ~ '^evidence/[A-Za-z0-9_/-]+$' AND storage_key NOT LIKE '%%//%%'))
)

""")
    op.execute('CREATE INDEX ix_evidence_request ON scanner_evidence (request_id, collected_at)')
    op.execute("""
CREATE TABLE result_processing_outcomes (
	id UUID NOT NULL,
	evidence_id UUID NOT NULL,
	attempt_id UUID NOT NULL,
	request_id UUID NOT NULL,
	assessment_id UUID NOT NULL,
	target_id UUID NOT NULL,
	processor VARCHAR(80) NOT NULL,
	processor_version VARCHAR(40) NOT NULL,
	run_number INTEGER NOT NULL,
	operation_id UUID NOT NULL,
	status VARCHAR(16) NOT NULL,
	started_at TIMESTAMP WITH TIME ZONE,
	finished_at TIMESTAMP WITH TIME ZONE,
	error_code VARCHAR(80),
	safe_diagnostic TEXT,
	observation_count INTEGER NOT NULL,
	is_partial BOOLEAN NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT fk_processing_evidence_binding FOREIGN KEY(evidence_id, attempt_id, request_id, assessment_id, target_id) REFERENCES scanner_evidence (id, attempt_id, request_id, assessment_id, target_id),
	CONSTRAINT uq_processing_binding UNIQUE (id, evidence_id, attempt_id, request_id, assessment_id, target_id),
	CONSTRAINT uq_processing_run UNIQUE (evidence_id, processor, processor_version, run_number),
	CONSTRAINT ck_processing_status CHECK (status IN ('Pending','Processing','Succeeded','Failed','Interrupted')),
	CONSTRAINT ck_processing_identity CHECK (run_number>0 AND observation_count>=0 AND btrim(processor)<>'' AND btrim(processor_version)<>''),
	CONSTRAINT ck_processing_start CHECK (status='Pending' OR started_at IS NOT NULL),
	CONSTRAINT ck_processing_finish CHECK ((status IN ('Pending','Processing') AND finished_at IS NULL) OR (status IN ('Succeeded','Failed','Interrupted') AND finished_at IS NOT NULL AND finished_at >= started_at)),
	CONSTRAINT ck_processing_error CHECK (status NOT IN ('Failed','Interrupted') OR (error_code IS NOT NULL AND btrim(error_code)<>'')),
	CONSTRAINT ck_processing_diagnostic_size CHECK (safe_diagnostic IS NULL OR octet_length(safe_diagnostic)<=2048),
	UNIQUE (operation_id)
)

""")
    op.execute('CREATE INDEX ix_processing_attempt ON result_processing_outcomes (attempt_id, created_at)')
    op.execute("""
CREATE TABLE security_observations (
	id UUID NOT NULL,
	processing_id UUID NOT NULL,
	evidence_id UUID NOT NULL,
	attempt_id UUID NOT NULL,
	request_id UUID NOT NULL,
	assessment_id UUID NOT NULL,
	target_id UUID NOT NULL,
	observation_type VARCHAR(80) NOT NULL,
	data JSONB NOT NULL,
	deduplication_key VARCHAR(64) NOT NULL,
	collected_at TIMESTAMP WITH TIME ZONE NOT NULL,
	processed_at TIMESTAMP WITH TIME ZONE NOT NULL,
	is_partial BOOLEAN NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT fk_observation_processing_binding FOREIGN KEY(processing_id, evidence_id, attempt_id, request_id, assessment_id, target_id) REFERENCES result_processing_outcomes (id, evidence_id, attempt_id, request_id, assessment_id, target_id),
	CONSTRAINT uq_observation_deduplication UNIQUE (evidence_id, deduplication_key),
	CONSTRAINT ck_observation_identity CHECK (deduplication_key ~ '^[0-9a-f]{64}$' AND btrim(observation_type)<>''),
	CONSTRAINT ck_observation_data CHECK (jsonb_typeof(data)='object' AND octet_length(data::text)<=16384),
	CONSTRAINT ck_observation_time CHECK (processed_at >= collected_at)
)

""")
    op.execute('CREATE INDEX ix_observation_assessment_target ON security_observations (assessment_id, target_id, collected_at)')
    op.execute("""
CREATE TABLE execution_events (
	id UUID NOT NULL,
	request_id UUID NOT NULL,
	assessment_id UUID NOT NULL,
	target_id UUID NOT NULL,
	attempt_id UUID,
	operation_id UUID NOT NULL,
	event_type VARCHAR(80) NOT NULL,
	actor_id UUID,
	system_origin VARCHAR(80),
	reason_code VARCHAR(80) NOT NULL,
	details JSONB NOT NULL,
	occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT fk_event_request_binding FOREIGN KEY(request_id, assessment_id, target_id) REFERENCES baseline_execution_requests (id, assessment_id, target_id),
	CONSTRAINT fk_event_attempt_binding FOREIGN KEY(attempt_id, request_id, assessment_id, target_id) REFERENCES execution_attempts (id, request_id, assessment_id, target_id),
	CONSTRAINT uq_execution_event_operation UNIQUE (request_id, operation_id),
	CONSTRAINT ck_execution_event_origin CHECK ((actor_id IS NULL) <> (system_origin IS NULL)),
	CONSTRAINT ck_execution_event_identity CHECK (btrim(event_type)<>'' AND btrim(reason_code)<>'' AND (system_origin IS NULL OR btrim(system_origin)<>'')),
	CONSTRAINT ck_execution_event_details CHECK (jsonb_typeof(details)='object' AND octet_length(details::text)<=4096),
	FOREIGN KEY(actor_id) REFERENCES users (id)
)

""")
    op.execute('CREATE INDEX ix_execution_event_timeline ON execution_events (request_id, occurred_at, id)')
    op.execute("""
CREATE FUNCTION protect_execution_attempt() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE q baseline_execution_requests%ROWTYPE;
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Execution attempts retain history'; END IF;
  IF TG_OP='INSERT' THEN
    SELECT * INTO q FROM baseline_execution_requests WHERE id=NEW.request_id FOR UPDATE;
    IF NOT FOUND OR q.status<>'Queued' OR NEW.status<>'Claimed'
       OR ROW(NEW.assessment_id,NEW.target_id,NEW.tool,NEW.profile_id,NEW.profile_version)
          IS DISTINCT FROM ROW(q.assessment_id,q.target_id,q.tool,q.profile_id,q.profile_version)
       OR NEW.parameters IS DISTINCT FROM q.authorized_activity::jsonb #> '{scheduling_preparation,plan}'
       OR NEW.parameter_digest IS DISTINCT FROM q.authorized_activity::jsonb #>> '{scheduling_preparation,parameter_digest}'
    THEN RAISE EXCEPTION 'Attempt does not match the queued restricted preparation'; END IF;
  ELSE
    IF OLD.status NOT IN ('Claimed','Running','RecoveryRequired') THEN
      RAISE EXCEPTION 'Terminal attempts are immutable';
    END IF;
    IF ROW(NEW.id,NEW.request_id,NEW.assessment_id,NEW.target_id,NEW.attempt_number,
           NEW.claim_id,NEW.worker_id,NEW.claimed_at,NEW.tool,NEW.profile_id,NEW.profile_version,
           NEW.parameters,NEW.parameter_digest,NEW.timeout_seconds,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.request_id,OLD.assessment_id,OLD.target_id,OLD.attempt_number,
           OLD.claim_id,OLD.worker_id,OLD.claimed_at,OLD.tool,OLD.profile_id,OLD.profile_version,
           OLD.parameters,OLD.parameter_digest,OLD.timeout_seconds,OLD.created_at)
       OR NEW.heartbeat_at<OLD.heartbeat_at OR NEW.lease_expires_at<OLD.lease_expires_at
       OR (OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at)
       OR (OLD.cancellation_requested_at IS NOT NULL AND
           ROW(NEW.cancellation_requested_at,NEW.cancellation_actor_id,NEW.cancellation_source,NEW.cancellation_reason)
             IS DISTINCT FROM ROW(OLD.cancellation_requested_at,OLD.cancellation_actor_id,OLD.cancellation_source,OLD.cancellation_reason))
       OR (NEW.status<>OLD.status AND NOT (
          (OLD.status='Claimed' AND NEW.status IN ('Running','RecoveryRequired','Failed','Blocked','Cancelled')) OR
          (OLD.status='Running' AND NEW.status IN ('RecoveryRequired','Succeeded','Failed','Stopped','Blocked','Cancelled')) OR
          (OLD.status='RecoveryRequired' AND NEW.status IN ('Succeeded','Failed','Stopped','Blocked','Cancelled'))))
    THEN RAISE EXCEPTION 'Attempt identity or lifecycle change is invalid'; END IF;
  END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER protect_execution_attempt BEFORE INSERT OR UPDATE OR DELETE ON execution_attempts
FOR EACH ROW EXECUTE FUNCTION protect_execution_attempt();

CREATE FUNCTION reject_execution_history_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Execution evidence and events are append-only'; END; $$;

CREATE FUNCTION validate_scanner_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a execution_attempts%ROWTYPE;
BEGIN
  SELECT * INTO a FROM execution_attempts WHERE id=NEW.attempt_id;
  IF NOT FOUND OR NEW.tool IS DISTINCT FROM a.tool THEN RAISE EXCEPTION 'Evidence tool binding is invalid'; END IF;
  IF a.tool='Nmap' AND a.profile_id='network-discovery' AND NEW.format NOT IN ('nmap-xml','stderr-text') THEN
    RAISE EXCEPTION 'Discovery evidence must retain original XML or stderr text';
  END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER validate_scanner_evidence BEFORE INSERT ON scanner_evidence
FOR EACH ROW EXECUTE FUNCTION validate_scanner_evidence();

CREATE FUNCTION protect_result_processing() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE n bigint;
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Processing outcomes retain history'; END IF;
  -- Serialize new processing with completion; do not reopen a sealed result.
  PERFORM 1 FROM baseline_execution_requests WHERE id=NEW.request_id AND status<>'Completed' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Completed execution processing is sealed'; END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.status<>'Pending' THEN RAISE EXCEPTION 'Processing must begin Pending'; END IF;
  ELSE
    IF OLD.status NOT IN ('Pending','Processing') THEN RAISE EXCEPTION 'Terminal processing outcomes are immutable'; END IF;
    IF ROW(NEW.id,NEW.evidence_id,NEW.attempt_id,NEW.request_id,NEW.assessment_id,NEW.target_id,
           NEW.processor,NEW.processor_version,NEW.run_number,NEW.operation_id,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.id,OLD.evidence_id,OLD.attempt_id,OLD.request_id,OLD.assessment_id,OLD.target_id,
           OLD.processor,OLD.processor_version,OLD.run_number,OLD.operation_id,OLD.created_at)
       OR (OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at)
       OR (NEW.status<>OLD.status AND NOT ((OLD.status='Pending' AND NEW.status='Processing') OR
           (OLD.status='Processing' AND NEW.status IN ('Succeeded','Failed','Interrupted'))))
    THEN RAISE EXCEPTION 'Processing identity or lifecycle change is invalid'; END IF;
    IF NEW.status IN ('Succeeded','Failed','Interrupted') THEN
      SELECT count(*) INTO n FROM security_observations WHERE processing_id=NEW.id;
      IF NEW.observation_count<>n OR (NOT NEW.is_partial AND EXISTS (
        SELECT 1 FROM scanner_evidence WHERE id=NEW.evidence_id AND is_partial
        UNION ALL SELECT 1 FROM security_observations WHERE processing_id=NEW.id AND is_partial))
      THEN RAISE EXCEPTION 'Processing counts or completeness are inconsistent'; END IF;
    END IF;
  END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER protect_result_processing BEFORE INSERT OR UPDATE OR DELETE ON result_processing_outcomes
FOR EACH ROW EXECUTE FUNCTION protect_result_processing();

CREATE FUNCTION validate_security_observation() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p result_processing_outcomes%ROWTYPE; a execution_attempts%ROWTYPE;
BEGIN
  SELECT * INTO p FROM result_processing_outcomes WHERE id=NEW.processing_id FOR UPDATE;
  IF NOT FOUND OR p.status<>'Processing' THEN RAISE EXCEPTION 'Observation requires active processing'; END IF;
  SELECT * INTO a FROM execution_attempts WHERE id=NEW.attempt_id;
  IF a.tool='Nmap' AND a.profile_id='network-discovery' THEN
    IF NEW.observation_type<>'host_discovery' OR
       NEW.data - ARRAY['address','status','reason','hostnames'] <> '{}'::jsonb OR
       NEW.data->>'address' IS DISTINCT FROM a.parameters->>'target' OR
       NEW.data->>'status' IS NULL OR NEW.data->>'status' NOT IN ('up','down','unknown')
    THEN RAISE EXCEPTION 'Discovery observations cannot imply ports, services or vulnerabilities'; END IF;
  END IF;
  IF NOT NEW.is_partial AND EXISTS (SELECT 1 FROM scanner_evidence WHERE id=NEW.evidence_id AND is_partial)
  THEN RAISE EXCEPTION 'Partial evidence requires a partial observation'; END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER validate_security_observation BEFORE INSERT ON security_observations
FOR EACH ROW EXECUTE FUNCTION validate_security_observation();

CREATE FUNCTION guard_execution_completion() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status='Completed' AND NEW.status IS DISTINCT FROM OLD.status AND NOT EXISTS (
    SELECT 1 FROM execution_attempts a JOIN result_processing_outcomes p ON p.attempt_id=a.id
    WHERE a.request_id=NEW.id AND a.status='Succeeded' AND p.status='Succeeded' AND NOT p.is_partial
      AND a.attempt_number=(SELECT max(x.attempt_number) FROM execution_attempts x WHERE x.request_id=NEW.id)
      AND NOT EXISTS (SELECT 1 FROM result_processing_outcomes latest
        WHERE latest.attempt_id=a.id
          AND latest.run_number=(SELECT max(x.run_number) FROM result_processing_outcomes x
            WHERE x.evidence_id=latest.evidence_id AND x.processor=latest.processor AND x.processor_version=latest.processor_version)
          AND (latest.status<>'Succeeded' OR latest.is_partial)))
  THEN RAISE EXCEPTION 'Completion requires scanner success and successful complete result processing'; END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER guard_execution_completion BEFORE UPDATE OF status ON baseline_execution_requests
FOR EACH ROW EXECUTE FUNCTION guard_execution_completion();
    """)
    for table in ('scanner_evidence','security_observations','execution_events'):
        op.execute(f'CREATE TRIGGER immutable_execution_history BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION reject_execution_history_change()')
    for table in ('execution_attempts','scanner_evidence','result_processing_outcomes','security_observations','execution_events'):
        op.execute(f'CREATE TRIGGER no_execution_history_truncate BEFORE TRUNCATE ON {table} FOR EACH STATEMENT EXECUTE FUNCTION reject_execution_history_change()')


def downgrade():
    # Lock parents first, matching insert order. Never silently erase evidence.
    op.execute('LOCK TABLE baseline_execution_requests, execution_attempts, scanner_evidence, result_processing_outcomes, security_observations, execution_events IN ACCESS EXCLUSIVE MODE')
    for table in ('execution_attempts','scanner_evidence','result_processing_outcomes','security_observations','execution_events'):
        op.execute(f"DO $$ BEGIN IF EXISTS (SELECT 1 FROM {table}) THEN RAISE EXCEPTION 'Cannot downgrade with execution persistence history'; END IF; END; $$")
    op.execute('DROP TRIGGER guard_execution_completion ON baseline_execution_requests')
    for table in ('execution_events','security_observations','result_processing_outcomes','scanner_evidence','execution_attempts'):
        op.drop_table(table)
    for function in ('guard_execution_completion','validate_security_observation','protect_result_processing','validate_scanner_evidence','reject_execution_history_change','protect_execution_attempt'):
        op.execute(f'DROP FUNCTION {function}()')
    op.drop_constraint('uq_execution_request_binding','baseline_execution_requests',type_='unique')
