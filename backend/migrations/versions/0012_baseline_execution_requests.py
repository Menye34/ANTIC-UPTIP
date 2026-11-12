"""Atomically queue baseline execution requests after analyst confirmation."""
from alembic import op

revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint('ck_assessments_start_state', 'assessments', type_='check')
    op.create_check_constraint('ck_assessments_start_state', 'assessments', "status IN ('Draft', 'Ready', 'Testing')")
    op.create_unique_constraint('uq_start_authorization_assessment', 'assessment_start_authorizations', ['id', 'assessment_id'])
    op.create_unique_constraint('uq_assessment_target_identity', 'assessment_targets', ['id', 'assessment_id'])
    op.execute("""
CREATE TABLE baseline_execution_requests (
    id UUID NOT NULL,
    assessment_id UUID NOT NULL,
    authorization_id UUID NOT NULL,
    target_id UUID NOT NULL,
    profile_id VARCHAR(80) NOT NULL,
    profile_version INTEGER NOT NULL,
    tool VARCHAR(80) NOT NULL,
    activity VARCHAR(160) NOT NULL,
    status VARCHAR(16) NOT NULL,
    authorized_activity JSON NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uq_baseline_execution_activity UNIQUE (authorization_id, target_id, profile_id),
    CONSTRAINT ck_baseline_execution_status CHECK (status IN ('Queued', 'Running', 'Completed', 'Failed', 'Stopped', 'Blocked', 'Cancelled')),
    CONSTRAINT ck_baseline_execution_profile_version CHECK (profile_version > 0),
    CONSTRAINT fk_execution_authorization_assessment FOREIGN KEY(authorization_id, assessment_id) REFERENCES assessment_start_authorizations (id, assessment_id),
    CONSTRAINT fk_execution_target_assessment FOREIGN KEY(target_id, assessment_id) REFERENCES assessment_targets (id, assessment_id)
)
    """)
    op.create_index('ix_execution_assessment_created', 'baseline_execution_requests', ['assessment_id', 'created_at', 'id'])
    op.execute("""
        CREATE FUNCTION protect_baseline_execution_input() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP <> 'UPDATE' THEN
                RAISE EXCEPTION 'Execution requests retain audit history';
            END IF;
            IF ROW(NEW.id, NEW.assessment_id, NEW.authorization_id, NEW.target_id,
                   NEW.profile_id, NEW.profile_version, NEW.tool, NEW.activity,
                   NEW.authorized_activity::text, NEW.created_at)
               IS DISTINCT FROM
               ROW(OLD.id, OLD.assessment_id, OLD.authorization_id, OLD.target_id,
                   OLD.profile_id, OLD.profile_version, OLD.tool, OLD.activity,
                   OLD.authorized_activity::text, OLD.created_at) THEN
                RAISE EXCEPTION 'Execution authorization input is immutable';
            END IF;
            RETURN NEW;
        END;
        $$
    """)
    op.execute("""
        CREATE TRIGGER protect_baseline_execution_input BEFORE UPDATE OR DELETE
        ON baseline_execution_requests FOR EACH ROW EXECUTE FUNCTION protect_baseline_execution_input()
    """)

    op.execute("""
        CREATE FUNCTION reject_baseline_execution_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Execution request history cannot be truncated';
        END;
        $$
    """)
    op.execute("""
        CREATE TRIGGER reject_baseline_execution_truncate BEFORE TRUNCATE
        ON baseline_execution_requests FOR EACH STATEMENT EXECUTE FUNCTION reject_baseline_execution_truncate()
    """)


def downgrade():
    op.execute('LOCK TABLE assessments, baseline_execution_requests IN ACCESS EXCLUSIVE MODE')
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM baseline_execution_requests)
                OR EXISTS (SELECT 1 FROM assessments WHERE status = 'Testing') THEN
                RAISE EXCEPTION 'Cannot downgrade Testing or execution history';
            END IF;
        END;
        $$
    """)
    op.drop_table('baseline_execution_requests')
    op.execute('DROP FUNCTION protect_baseline_execution_input()')
    op.execute('DROP FUNCTION reject_baseline_execution_truncate()')
    op.drop_constraint('uq_assessment_target_identity', 'assessment_targets', type_='unique')
    op.drop_constraint('uq_start_authorization_assessment', 'assessment_start_authorizations', type_='unique')
    op.drop_constraint('ck_assessments_start_state', 'assessments', type_='check')
    op.create_check_constraint('ck_assessments_start_state', 'assessments', "status IN ('Draft', 'Ready')")
