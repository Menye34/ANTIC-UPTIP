from pathlib import Path

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import DBAPIError

from app.models import ExecutionPolicyVersion


def test_policy_definition_validation_rejects_invalid_document(db):
    db.add(ExecutionPolicyVersion(policy_id='invalid', version=1, digest='a' * 64, definition={}))
    with pytest.raises(ValueError):
        db.flush()
    db.rollback()


def test_authorization_migration_preserves_empty_unseeded_schema(engine):
    config = Config(str(Path(__file__).resolve().parents[1] / 'alembic.ini'))
    tables = {'execution_policy_versions', 'execution_policy_approvals',
              'assessment_start_evidence', 'authorization_record_revocations'}
    command.downgrade(config, '0009')
    try:
        assert tables.isdisjoint(inspect(engine).get_table_names())
        command.upgrade(config, '0010')
        schema = inspect(engine)
        assert tables <= set(schema.get_table_names())
        bindings = {tuple(key['constrained_columns']) for key in schema.get_foreign_keys('assessment_start_evidence')}
        assert ('evaluation_id', 'assessment_id', 'target_id', 'evaluation_fingerprint') in bindings
        assert ('approval_reference', 'policy_digest') in bindings
        with engine.connect() as connection:
            for table in tables:
                assert connection.scalar(text(f'SELECT count(*) FROM {table}')) == 0
        for table in tables:
            with pytest.raises(DBAPIError, match='append-only'):
                with engine.begin() as connection:
                    connection.execute(text(f'DELETE FROM {table}'))
    finally:
        command.upgrade(config, 'head')
