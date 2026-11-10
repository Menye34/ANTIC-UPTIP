"""Store governed policy versions, approvals, and bound Start evidence."""

from alembic import op

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None

_TABLES = (
    'execution_policy_versions',
    'execution_policy_approvals',
    'assessment_start_evidence',
    'authorization_record_revocations',
)

def upgrade():
    op.create_unique_constraint('uq_baseline_evaluation_binding', 'baseline_evaluations',
                                ['id', 'assessment_id', 'target_id', 'fingerprint'])
    op.execute("""
        CREATE TABLE execution_policy_versions (
            policy_id VARCHAR(120) NOT NULL,
            version INTEGER NOT NULL,
            digest VARCHAR(64) NOT NULL,
            definition JSON NOT NULL,
            recorded_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
            PRIMARY KEY (policy_id, version),
            CONSTRAINT ck_policy_version_positive CHECK (version > 0),
            CONSTRAINT ck_policy_digest CHECK (digest ~ '^[0-9a-f]{64}$'),
            CONSTRAINT ck_policy_definition_object CHECK (json_typeof(definition) = 'object'),
            CONSTRAINT ck_policy_id_present CHECK (btrim(policy_id) <> ''),
            UNIQUE (digest)
        )
    """)
    op.execute("""
        CREATE TABLE execution_policy_approvals (
            reference VARCHAR(160) NOT NULL,
            policy_digest VARCHAR(64) NOT NULL,
            provenance TEXT NOT NULL,
            valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
            valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
            recorded_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
            PRIMARY KEY (reference),
            CONSTRAINT uq_policy_approval_binding UNIQUE (reference, policy_digest),
            CONSTRAINT ck_policy_approval_window CHECK (valid_until > valid_from),
            CONSTRAINT ck_policy_approval_identity CHECK (btrim(reference) <> '' AND btrim(provenance) <> ''),
            FOREIGN KEY(policy_digest) REFERENCES execution_policy_versions (digest)
        )
    """)
    op.create_index('ix_execution_policy_approvals_policy_digest', 'execution_policy_approvals', ['policy_digest'])
    op.execute("""
        CREATE TABLE assessment_start_evidence (
            reference VARCHAR(160) NOT NULL,
            assessment_id UUID NOT NULL,
            target_id UUID NOT NULL,
            evaluation_id UUID NOT NULL,
            evaluation_fingerprint VARCHAR(64) NOT NULL,
            approval_reference VARCHAR(160) NOT NULL,
            policy_digest VARCHAR(64) NOT NULL,
            provenance TEXT NOT NULL,
            valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
            valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
            evidence JSON NOT NULL,
            recorded_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
            PRIMARY KEY (reference),
            CONSTRAINT fk_start_evidence_evaluation_binding FOREIGN KEY(evaluation_id, assessment_id, target_id, evaluation_fingerprint) REFERENCES baseline_evaluations (id, assessment_id, target_id, fingerprint),
            CONSTRAINT fk_start_evidence_approval_binding FOREIGN KEY(approval_reference, policy_digest) REFERENCES execution_policy_approvals (reference, policy_digest),
            CONSTRAINT ck_start_evidence_window CHECK (valid_until > valid_from),
            CONSTRAINT ck_start_evidence_object CHECK (json_typeof(evidence) = 'object'),
            CONSTRAINT ck_start_evidence_identity CHECK (btrim(reference) <> '' AND btrim(provenance) <> ''),
            FOREIGN KEY(assessment_id) REFERENCES assessments (id)
        )
    """)
    op.create_index('ix_assessment_start_evidence_evaluation_id', 'assessment_start_evidence', ['evaluation_id'])
    op.create_index('ix_start_evidence_approval', 'assessment_start_evidence', ['approval_reference', 'policy_digest'])
    op.create_index('ix_start_evidence_binding', 'assessment_start_evidence', ['assessment_id', 'target_id', 'evaluation_fingerprint', 'policy_digest'])
    op.execute("""
        CREATE TABLE authorization_record_revocations (
            id UUID NOT NULL,
            approval_reference VARCHAR(160),
            evidence_reference VARCHAR(160),
            reason TEXT NOT NULL,
            provenance TEXT NOT NULL,
            recorded_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
            PRIMARY KEY (id),
            CONSTRAINT ck_authorization_revocation_subject CHECK ((approval_reference IS NULL) <> (evidence_reference IS NULL)),
            CONSTRAINT ck_authorization_revocation_reason CHECK (btrim(reason) <> '' AND btrim(provenance) <> ''),
            UNIQUE (approval_reference),
            FOREIGN KEY(approval_reference) REFERENCES execution_policy_approvals (reference),
            UNIQUE (evidence_reference),
            FOREIGN KEY(evidence_reference) REFERENCES assessment_start_evidence (reference)
        )
    """)

    op.execute("""
        CREATE FUNCTION reject_governed_authorization_change() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE has_history boolean;
        BEGIN
            IF TG_OP = 'TRUNCATE' THEN
                EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.%I)', TG_TABLE_SCHEMA, TG_TABLE_NAME)
                    INTO has_history;
                IF NOT has_history THEN
                    RETURN NULL;
                END IF;
            END IF;
            RAISE EXCEPTION 'Governed authorization records are append-only';
        END;
        $$
    """)
    for table in _TABLES:
        op.execute(f"""
            CREATE TRIGGER reject_governed_authorization_change
            BEFORE UPDATE OR DELETE OR TRUNCATE ON {table}
            FOR EACH STATEMENT EXECUTE FUNCTION reject_governed_authorization_change()
        """)


def downgrade():
    op.execute(f"LOCK TABLE {', '.join(_TABLES)} IN ACCESS EXCLUSIVE MODE")
    for table in _TABLES:
        op.execute(f"""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM {table}) THEN
                    RAISE EXCEPTION 'Cannot downgrade with governed authorization history';
                END IF;
            END;
            $$
        """)
    for table in reversed(_TABLES):
        op.drop_table(table)
    op.execute('DROP FUNCTION reject_governed_authorization_change()')
    op.drop_constraint('uq_baseline_evaluation_binding', 'baseline_evaluations', type_='unique')
