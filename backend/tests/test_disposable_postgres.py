"""Destructive test administration must fail before creating/dropping anything."""
from unittest.mock import MagicMock
import pytest
import disposable_postgres as disposable

ADMIN = 'postgresql+psycopg://postgres@127.0.0.1:55486/postgres'
OWNER = 'postgresql+psycopg://uptip@127.0.0.1:55486/uptip_test_readiness_fix'
RUNTIME = 'postgresql+psycopg://uptip_runtime@127.0.0.1:55486/uptip_test_readiness_fix'
NAME = 'uptip_test_schedule_' + 'a' * 32


@pytest.mark.parametrize('name,admin,owner,runtime,test', [
    ('uptip', ADMIN, OWNER, RUNTIME, OWNER),
    (NAME, ADMIN.replace('127.0.0.1', 'production.example'), OWNER, RUNTIME, OWNER),
    (NAME, ADMIN, OWNER.replace('uptip_test_readiness_fix', 'uptip'), RUNTIME, OWNER),
    (NAME, ADMIN, OWNER, RUNTIME.replace('55486', '5432'), OWNER),
    (NAME, ADMIN + '?options=unsafe', OWNER, RUNTIME, OWNER),
    (NAME, ADMIN, OWNER, RUNTIME, OWNER.replace('uptip_test_readiness_fix', 'uptip')),
])
def test_invalid_destination_never_connects(monkeypatch, name, admin, owner, runtime, test):
    connect = MagicMock()
    monkeypatch.setattr(disposable, 'create_engine', connect)
    with pytest.raises(RuntimeError, match='unverified'):
        disposable.scheduling_database(name, admin, owner, runtime, test)
    connect.assert_not_called()


def test_missing_cluster_marker_never_executes_destructive_sql(monkeypatch):
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    connection.scalar.return_value = None
    monkeypatch.setattr(disposable, 'create_engine', lambda *a, **kw: engine)
    administer, _, _ = disposable.scheduling_database(NAME, ADMIN, OWNER, RUNTIME, OWNER)
    with pytest.raises(RuntimeError, match='marker missing'):
        administer('create')
    connection.execute.assert_not_called()


def test_drop_requires_exact_database_owner_and_marker(monkeypatch):
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    connection.scalar.return_value = disposable.CLUSTER_MARKER
    base, wrong = MagicMock(), MagicMock()
    base.one_or_none.return_value = ('uptip', 'UPTIP disposable integration test database')
    wrong.one_or_none.return_value = ('uptip', 'not disposable')
    connection.execute.side_effect = [base, wrong]
    monkeypatch.setattr(disposable, 'create_engine', lambda *a, **kw: engine)
    administer, _, _ = disposable.scheduling_database(NAME, ADMIN, OWNER, RUNTIME, OWNER)
    with pytest.raises(RuntimeError, match='Refusing to drop'):
        administer('drop')
    assert all(str(call.args[0]).startswith('SELECT') for call in connection.execute.call_args_list)
