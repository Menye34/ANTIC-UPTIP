"""Link consolidated findings to recommended-test observations."""
from alembic import op
import sqlalchemy as sa

revision = '0031'
down_revision = '0030'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'finding_recommended_observations',
        sa.Column('finding_id', sa.UUID(), primary_key=True),
        sa.Column(
            'observation_id', sa.UUID(),
            sa.ForeignKey('recommended_observations.id'),
            primary_key=True
        ),
        sa.Column(
            'assessment_id', sa.UUID(),
            sa.ForeignKey('assessments.id'),
            nullable=False
        ),
        sa.Column('match_reason', sa.String(80), nullable=False),
        sa.ForeignKeyConstraint(
            ['finding_id', 'assessment_id'],
            ['consolidated_findings.id',
             'consolidated_findings.assessment_id'],
            name='fk_finding_recommended_assessment'
        ),
        sa.UniqueConstraint(
            'observation_id',
            name='uq_finding_recommended_observation_once'
        )
    )

    op.create_index(
        'ix_finding_recommended_assessment',
        'finding_recommended_observations',
        ['assessment_id', 'finding_id']
    )

    op.execute("""
        CREATE FUNCTION
        public.check_finding_recommended_assessment()
        RETURNS trigger AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM public.recommended_observations o
                WHERE o.id = NEW.observation_id
                AND o.assessment_id = NEW.assessment_id
            ) THEN
                RAISE EXCEPTION
                    'recommended finding observation assessment mismatch';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER trg_finding_recommended_assessment
        BEFORE INSERT OR UPDATE
        ON public.finding_recommended_observations
        FOR EACH ROW EXECUTE FUNCTION
        public.check_finding_recommended_assessment();
    """)

    op.execute("""
        GRANT SELECT, INSERT
        ON public.finding_recommended_observations
        TO uptip_runtime
    """)


def downgrade():
    raise RuntimeError(
        'Automatic downgrade disabled to preserve finding evidence.'
    )
