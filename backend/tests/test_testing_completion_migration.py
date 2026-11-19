"""Task 1: migration/history guards on one marked disposable database per test."""
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from app.config import get_settings
from sqlalchemy.exc import DBAPIError

from app.models import Assessment, TestingCompletionEvent as CompletionEvent, TestingRecommendationDecision as Decision
from test_assessments import add_analyst, sign_in
from test_scheduling_start import scheduling_concurrency  # noqa: F401

pytestmark = pytest.mark.parametrize('scheduling_concurrency', ['empty'], indirect=True)


@pytest.fixture
def history_db(scheduling_concurrency):
    app, factory, *_ = scheduling_concurrency
    root = Path(__file__).resolve().parents[1]
    config = Config(str(root / 'alembic.ini'))
    config.set_main_option('script_location', str(root / 'migrations'))
    command.upgrade(config, '0021')
    return app, factory, config


def seed(app, factory, *, receipt=False, decision=False, status='Testing'):
    with factory() as db, TestClient(app, base_url='https://testserver') as client:
        client.headers['Origin'] = 'https://testserver'
        actor = add_analyst(db, 'migration-history-owner')
        response = client.post('/api/v1/assessments', headers=sign_in(client, actor.username),
                               json={'name': 'Disposable completion history'})
        assert response.status_code == 201
        identifier = UUID(response.json()['id'])
        db.get(Assessment, identifier).status = status
        if decision:
            db.add(Decision(assessment_id=identifier, recommendation_id='a' * 64,
                            actor_id=actor.id, decision='Deferred', decided_at=datetime.now(timezone.utc)))
        if receipt:
            db.add(CompletionEvent(assessment_id=identifier, actor_id=actor.id,
                                  completed_at=datetime.now(timezone.utc), snapshot={'synthetic': True}))
        db.commit()
        return identifier, actor.id


def grants(factory):
    with factory() as db:
        return {(table, privilege): db.scalar(text(
            'SELECT has_table_privilege(:role,:table,:privilege)'),
            {'role': 'uptip_runtime', 'table': table, 'privilege': privilege})
            for table in ('testing_completion_events', 'testing_recommendation_decisions')
            for privilege in ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')}


def test_upgrade_preserves_existing_records_models_and_runtime_grants(history_db):
    from sqlalchemy import inspect
    app, factory, config = history_db
    identifier, actor = seed(app, factory, receipt=True, decision=True, status='Finding Review')
    before = grants(factory)
    command.upgrade(config, '0022')
    assert grants(factory) == before
    assert before['testing_completion_events', 'SELECT'] and before['testing_completion_events', 'INSERT']
    assert not any(before['testing_completion_events', p] for p in ('UPDATE', 'DELETE', 'TRUNCATE'))
    assert before['testing_recommendation_decisions', 'UPDATE']
    assert not any(before['testing_recommendation_decisions', p] for p in ('DELETE', 'TRUNCATE'))
    with factory() as db:
        assert db.get(CompletionEvent, identifier).snapshot == {'synthetic': True}
        assert db.get(CompletionEvent, identifier).actor_id == actor
        assert db.get(Decision, (identifier, 'a' * 64)).decision == 'Deferred'
        assert db.get(Assessment, identifier).status == 'Finding Review'
        assert db.scalar(text('SELECT version_num FROM alembic_version')) == '0022'
        assert db.scalar(text("SELECT prosecdef FROM pg_proc WHERE oid='public.protect_testing_decision_history()'::regprocedure"))
        assert not db.scalar(text("SELECT has_function_privilege('uptip_runtime','public.protect_testing_decision_history()','EXECUTE')"))
        inspector = inspect(db.bind)
        for model in (CompletionEvent, Decision):
            assert {c['name'] for c in inspector.get_columns(model.__tablename__)} == set(model.__table__.columns.keys())
            assert len(inspector.get_foreign_keys(model.__tablename__)) == 2


def test_history_cannot_be_rewritten_deleted_truncated_or_reopened(history_db):
    app, factory, config = history_db
    identifier, _ = seed(app, factory, receipt=True, decision=True, status='Finding Review')
    command.upgrade(config, '0022')
    statements = [
        "UPDATE testing_completion_events SET snapshot='{}'::json",
        'DELETE FROM testing_completion_events', 'TRUNCATE testing_completion_events',
        'DELETE FROM testing_recommendation_decisions', 'TRUNCATE testing_recommendation_decisions',
        "UPDATE testing_recommendation_decisions SET decision='Reviewed'",
        *[f"UPDATE assessments SET status='{state}' WHERE id=:id" for state in ('Draft', 'Ready', 'Testing')],
    ]
    with factory() as db:
        for statement in statements:
            with pytest.raises(DBAPIError, match='append-only|immutable|cannot be reopened'):
                with db.begin_nested():
                    db.execute(text(statement), {'id': identifier})
        assert db.get(CompletionEvent, identifier).snapshot == {'synthetic': True}
        assert db.get(Decision, (identifier, 'a' * 64)).decision == 'Deferred'
        assert db.get(Assessment, identifier).status == 'Finding Review'


def test_decisions_remain_mutable_during_testing_and_identity_cannot_move(history_db):
    app, factory, config = history_db
    identifier, _ = seed(app, factory, decision=True)
    command.upgrade(config, '0022')
    runtime_url = make_url(get_settings().database_url).set(database=factory.kw['bind'].url.database)
    runtime = create_engine(runtime_url, hide_parameters=True)
    try:
        with runtime.begin() as connection:
            connection.execute(text("UPDATE testing_recommendation_decisions SET decision='Reviewed' WHERE assessment_id=:id"), {'id': identifier})
            with pytest.raises(DBAPIError, match='identity is immutable'):
                with connection.begin_nested():
                    connection.execute(text("UPDATE testing_recommendation_decisions SET recommendation_id=:key"), {'key': 'b' * 64})
    finally:
        runtime.dispose()
    with factory() as db:
        assert db.get(Decision, (identifier, 'a' * 64)).decision == 'Reviewed'


@pytest.mark.parametrize('history', ['receipt', 'decision', 'finding_review'])
def test_downgrade_refuses_history_and_rolls_back_without_erasing_or_reopening(history_db, history):
    app, factory, config = history_db
    identifier, _ = seed(app, factory, receipt=history == 'receipt', decision=history == 'decision',
                         status='Finding Review' if history != 'decision' else 'Testing')
    command.upgrade(config, '0022')
    before = grants(factory)
    with pytest.raises(DBAPIError, match='Cannot downgrade with Testing Completion history'):
        command.downgrade(config, '0020')
    assert grants(factory) == before
    with factory() as db:
        assert db.scalar(text('SELECT version_num FROM alembic_version')) == '0022'
        assert db.get(Assessment, identifier).status == ('Testing' if history == 'decision' else 'Finding Review')
        assert bool(db.get(CompletionEvent, identifier)) == (history == 'receipt')
        assert bool(db.get(Decision, (identifier, 'a' * 64))) == (history == 'decision')
        assert db.scalar(text("SELECT count(*) FROM pg_trigger WHERE tgname='immutable_testing_completion'")) == 1


def test_empty_history_downgrade_reapply_preserves_draft(history_db):
    app, factory, config = history_db
    identifier, actor = seed(app, factory, status='Draft')
    command.upgrade(config, '0022')
    before = grants(factory)
    command.downgrade(config, '0020')
    with factory() as db:
        assert db.scalar(text('SELECT version_num FROM alembic_version')) == '0020'
        assert db.get(Assessment, identifier).status == 'Draft'
        assert db.get(Assessment, identifier).creator_id == actor
    command.upgrade(config, '0022')
    assert grants(factory) == before


def test_real_completion_transaction_still_works_with_history_guards(history_db, monkeypatch, tmp_path):
    from test_scheduling_start import prepared, get_review, confirm
    from test_execution_orchestration import FakeAdapter, BorrowedFactory
    from app.execution_orchestration import ExecutionRunner
    from app.execution_results import EvidenceStore
    app, factory, config = history_db
    command.upgrade(config, '0022')
    with factory() as db, TestClient(app, base_url='https://testserver') as client:
        client.headers['Origin'] = 'https://testserver'
        path, headers, _ = prepared.__wrapped__(client, db, monkeypatch)
        start = confirm(client, path, headers, get_review(client, path)['start_review'])
        assert start.status_code == 201
        tmp_path.chmod(0o700)
        assert ExecutionRunner(BorrowedFactory(db), FakeAdapter(), EvidenceStore(tmp_path), 'synthetic-history-test').run(
            UUID(start.json()['queued_execution_ids'][0]))
        db.commit()
        review = client.get(path + '/testing/completion').json()
        for item in review['recommendations']:
            assert client.post(path + '/testing/completion/decisions', headers=headers,
                               json={'recommendation_id': item['id'], 'decision': 'Reviewed'}).status_code == 200
        review = client.get(path + '/testing/completion').json()
        assert review['ready'] is True
        completed = client.post(path + '/testing/completion', headers=headers,
                                json={'snapshot_digest': review['snapshot_digest'], 'confirmed': True})
        assert completed.status_code == 200, completed.text
        assert completed.json()['lifecycle_status'] == 'Finding Review'
        assert completed.json()['completion'] is not None
        assert client.get(path + '/testing/completion').json()['completion'] is not None


def test_concurrent_decision_update_waits_then_rejects_completed_history(history_db):
    from concurrent.futures import ThreadPoolExecutor, TimeoutError
    from threading import Event
    app, factory, config = history_db
    identifier, actor = seed(app, factory, decision=True)
    command.upgrade(config, '0022')
    entered = Event()
    def update():
        with factory.begin() as db:
            entered.set()
            with pytest.raises(DBAPIError, match='Completed testing decisions are immutable'):
                db.execute(text("UPDATE testing_recommendation_decisions SET decision='Reviewed' WHERE assessment_id=:id"), {'id': identifier})
            db.rollback()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory.begin() as db:
            db.execute(text('SELECT id FROM assessments WHERE id=:id FOR UPDATE'), {'id': identifier})
            db.add(CompletionEvent(assessment_id=identifier, actor_id=actor,
                                  completed_at=datetime.now(timezone.utc), snapshot={'synthetic': True}))
            db.get(Assessment, identifier).status = 'Finding Review'
            db.flush()
            future = pool.submit(update)
            assert entered.wait(timeout=5)
            with pytest.raises(TimeoutError):
                future.result(timeout=.2)
        future.result(timeout=5)
    with factory() as db:
        assert db.get(Decision, (identifier, 'a' * 64)).decision == 'Deferred'
        assert db.get(Assessment, identifier).status == 'Finding Review'
