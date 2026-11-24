"""Consolidated findings and immutable source-observation relationships."""
from alembic import op
import sqlalchemy as sa

revision = '0030'
down_revision = '0029'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())

    existing = {
        name for name in (
            'consolidated_findings',
            'finding_observations'
        )
        if inspector.has_table(name, schema='public')
    }

    if existing:
        if len(existing) != 2:
            raise RuntimeError(
                'Incomplete existing Findings schema.'
            )

        expected = {
            'consolidated_findings': {
                'id', 'assessment_id', 'identity_key',
                'rule_version', 'title', 'severity',
                'affected_target', 'source', 'source_test',
                'description', 'impact', 'security_control',
                'observed_condition', 'detected_issue',
                'remediation', 'created_at', 'updated_at'
            },
            'finding_observations': {
                'finding_id', 'observation_id',
                'assessment_id', 'match_reason'
            }
        }

        for table, required in expected.items():
            columns = inspector.get_columns(
                table, schema='public'
            )
            actual = {column['name'] for column in columns}

            if actual != required:
                raise RuntimeError(
                    f'Incompatible Findings columns: {table}'
                )

            if any(column['nullable'] for column in columns):
                raise RuntimeError(
                    f'Unexpected nullable columns: {table}'
                )

        for table, required in {
            'consolidated_findings': {
                'uq_finding_assessment',
                'uq_finding_assessment_identity'
            },
            'finding_observations': {
                'uq_finding_observation_once'
            }
        }.items():
            actual = {
                item['name']
                for item in inspector.get_unique_constraints(
                    table, schema='public'
                )
            }
            if not required.issubset(actual):
                raise RuntimeError(
                    f'Missing Findings constraints: {table}'
                )

        checks = {
            item['name']
            for item in inspector.get_check_constraints(
                'consolidated_findings', schema='public'
            )
        }

        if not {
            'ck_finding_identity',
            'ck_finding_severity'
        }.issubset(checks):
            raise RuntimeError(
                'Missing Findings check constraints.'
            )

        trigger = op.get_bind().execute(sa.text("""
            SELECT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgrelid =
                    'public.finding_observations'::regclass
                AND tgname =
                    'trg_finding_observation_assessment'
                AND tgenabled IN ('O', 'A')
                AND NOT tgisinternal
            )
        """)).scalar()

        if not trigger:
            raise RuntimeError(
                'Missing Findings assessment isolation trigger.'
            )

        op.execute(
            "GRANT SELECT, INSERT ON "
            "public.consolidated_findings TO uptip_runtime"
        )
        op.execute(
            "GRANT SELECT, INSERT ON "
            "public.finding_observations TO uptip_runtime"
        )

        return

    # Fresh installation: create the Findings schema.

    op.create_table('consolidated_findings',
        sa.Column('id', sa.UUID(), primary_key=True),
        sa.Column('assessment_id', sa.UUID(), sa.ForeignKey('assessments.id'), nullable=False),
        sa.Column('identity_key', sa.String(64), nullable=False),
        sa.Column('rule_version', sa.String(40), nullable=False),
        sa.Column('title', sa.String(240), nullable=False),
        sa.Column('severity', sa.String(16), nullable=False),
        sa.Column('affected_target', sa.String(1024), nullable=False),
        sa.Column('source', sa.String(160), nullable=False),
        sa.Column('source_test', sa.String(160), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('impact', sa.Text(), nullable=False),
        sa.Column('security_control', sa.String(240), nullable=False),
        sa.Column('observed_condition', sa.Text(), nullable=False),
        sa.Column('detected_issue', sa.Text(), nullable=False),
        sa.Column('remediation', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint('assessment_id', 'identity_key', name='uq_finding_assessment_identity'),
        sa.UniqueConstraint('id', 'assessment_id', name='uq_finding_assessment'),
        sa.CheckConstraint("severity IN ('Critical','High','Medium','Low')", name='ck_finding_severity'),
        sa.CheckConstraint("btrim(title)<>'' AND btrim(identity_key)<>'' AND btrim(rule_version)<>''", name='ck_finding_identity'))
    op.create_index('ix_findings_assessment_severity', 'consolidated_findings', ['assessment_id', 'severity'])
    op.create_table('finding_observations',
        sa.Column('finding_id', sa.UUID(), primary_key=True),
        sa.Column('observation_id', sa.UUID(), sa.ForeignKey('security_observations.id'), primary_key=True),
        sa.Column('assessment_id', sa.UUID(), sa.ForeignKey('assessments.id'), nullable=False),
        sa.Column('match_reason', sa.String(80), nullable=False),
        sa.ForeignKeyConstraint(['finding_id', 'assessment_id'],
            ['consolidated_findings.id', 'consolidated_findings.assessment_id'],
            name='fk_finding_link_assessment'),
        sa.UniqueConstraint('observation_id', name='uq_finding_observation_once'))
    op.create_index('ix_finding_observations_assessment', 'finding_observations', ['assessment_id', 'finding_id'])
    # Runtime can insert consolidated findings during authorized completion,
    # but cannot mutate or delete historical findings.
    op.execute("GRANT SELECT, INSERT ON public.consolidated_findings TO uptip_runtime")
    op.execute("GRANT SELECT, INSERT ON public.finding_observations TO uptip_runtime")
    # The observation's assessment must match its finding's assessment.
    op.execute("""
CREATE OR REPLACE FUNCTION check_finding_observation_assessment() RETURNS trigger AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM security_observations o
                WHERE o.id = NEW.observation_id AND o.assessment_id = NEW.assessment_id)
 THEN RAISE EXCEPTION 'finding observation assessment mismatch'; END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_finding_observation_assessment
 BEFORE INSERT OR UPDATE ON finding_observations
 FOR EACH ROW EXECUTE FUNCTION check_finding_observation_assessment();
""")


def downgrade():
    raise RuntimeError(
        'Automatic downgrade is disabled to preserve Findings data.'
    )
