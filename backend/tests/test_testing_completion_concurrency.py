"""Real concurrent transactions; each test owns a marked disposable database."""
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from pathlib import Path
from threading import Barrier, Event
from uuid import UUID

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import event, func, select

from app.execution_orchestration import ExecutionRunner
from app.execution_results import EvidenceStore
from app.models import Assessment, TestingCompletionEvent as CompletionEvent, TestingRecommendationDecision as Decision
from test_execution_orchestration import FakeAdapter, BorrowedFactory
from test_scheduling_start import prepared, get_review, confirm, scheduling_concurrency  # noqa: F401
from test_testing_completion_contract import reviewed

pytestmark = pytest.mark.parametrize('scheduling_concurrency', ['empty'], indirect=True)


@pytest.fixture
def committed_completion(scheduling_concurrency, monkeypatch, tmp_path):
    from recommendation_fixtures import mock_recommendations
    mock_recommendations(monkeypatch)
    app, factory, *_ = scheduling_concurrency
    backend = Path(__file__).resolve().parents[1]
    config = Config(str(backend / 'alembic.ini'))
    config.set_main_option('script_location', str(backend / 'migrations'))
    command.upgrade(config, '0022')
    with factory() as db, TestClient(app, base_url='https://testserver') as client:
        client.headers['Origin'] = 'https://testserver'
        path, headers, _ = prepared.__wrapped__(client, db, monkeypatch)
        result = confirm(client, path, headers, get_review(client, path)['start_review'])
        assert result.status_code == 201
        tmp_path.chmod(0o700)
        assert ExecutionRunner(BorrowedFactory(db), FakeAdapter(), EvidenceStore(tmp_path), 'concurrency-fixture').run(
            UUID(result.json()['queued_execution_ids'][0]))
        db.commit()
        review = reviewed(client, path, headers)
        assert review['ready']
        cookies = dict(client.cookies)
    return app, factory, path, headers, cookies, review


def post(client, path, headers, review):
    return client.post(path + '/testing/completion', headers=headers,
                       json={'confirmed': True, 'snapshot_digest': review['snapshot_digest']})


def test_completion_get_has_one_snapshot_during_concurrent_completion(committed_completion):
    app, factory, path, headers, cookies, review = committed_completion
    engine = factory.kw['bind']
    triggered = False
    with TestClient(app, base_url='https://testserver', cookies=cookies) as writer:
        writer.headers['Origin'] = 'https://testserver'
        def finish_after_select(conn, cursor, sql, *args):
            nonlocal triggered
            if triggered or 'json_agg' not in sql:
                return
            triggered = True
            response = post(writer, path, headers, review)
            assert response.status_code == 200, response.text
        event.listen(engine, 'after_cursor_execute', finish_after_select)
        try:
            with TestClient(app, base_url='https://testserver', cookies=cookies) as reader:
                response = reader.get(path + '/testing/completion')
        finally:
            event.remove(engine, 'after_cursor_execute', finish_after_select)
        assert triggered and response.status_code == 200, response.text
        before = response.json()
        assert before['lifecycle_status'] == 'Testing' and before['ready']
        assert before['completion'] is None
        after = writer.get(path + '/testing/completion').json()
        assert after['lifecycle_status'] == 'Finding Review' and not after['ready']
        assert after['completion']['snapshot_digest'] == before['snapshot_digest']


def test_concurrent_completion_has_one_receipt_and_transition(committed_completion):
    app, factory, path, headers, cookies, review = committed_completion
    barrier = Barrier(2)
    def send():
        with TestClient(app, base_url='https://testserver', cookies=cookies) as client:
            client.headers['Origin'] = 'https://testserver'
            barrier.wait(timeout=5)
            return post(client, path, headers, review).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(send) for _ in range(2)]
        assert sorted(f.result(timeout=10) for f in futures) == [200, 409]
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(CompletionEvent)) == 1
        assert db.scalar(select(Assessment.status)) == 'Finding Review'


def test_decision_change_invalidates_review_without_transition(committed_completion):
    app, factory, path, headers, cookies, review = committed_completion
    rid = review['recommendations'][0]['id']
    with TestClient(app, base_url='https://testserver', cookies=cookies) as client:
        client.headers['Origin'] = 'https://testserver'
        assert client.post(path + '/testing/completion/decisions', headers=headers,
                           json={'recommendation_id': rid, 'decision': 'Deferred'}).status_code == 200
        assert post(client, path, headers, review).status_code == 409
        new = client.get(path + '/testing/completion').json()
        assert new['snapshot_digest'] != review['snapshot_digest'] and not new['ready']
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(CompletionEvent)) == 0
        assert db.scalar(select(Assessment.status)) == 'Testing'


def test_decision_writer_waits_and_cannot_change_completed_review(committed_completion):
    app, factory, path, headers, cookies, review = committed_completion
    entered = Event()
    launched = False
    future = None
    rid = review['recommendations'][0]['id']
    def decision():
        with TestClient(app, base_url='https://testserver', cookies=cookies) as client:
            client.headers['Origin'] = 'https://testserver'
            entered.set()
            return client.post(path + '/testing/completion/decisions', headers=headers,
                               json={'recommendation_id': rid, 'decision': 'Deferred'}).status_code
    engine = factory.kw['bind']
    with ThreadPoolExecutor(max_workers=1) as pool:
        def after_parent_lock(conn, cursor, sql, *args):
            nonlocal launched, future
            if launched or 'FROM assessments' not in sql or 'FOR UPDATE' not in sql:
                return
            launched = True
            future = pool.submit(decision)
            assert entered.wait(timeout=5)
            with pytest.raises(TimeoutError):
                future.result(timeout=.2)
        event.listen(engine, 'after_cursor_execute', after_parent_lock)
        try:
            with TestClient(app, base_url='https://testserver', cookies=cookies) as client:
                client.headers['Origin'] = 'https://testserver'
                result = post(client, path, headers, review)
        finally:
            event.remove(engine, 'after_cursor_execute', after_parent_lock)
        assert result.status_code == 200, result.text
        assert launched and future.result(timeout=10) == 409
    with factory() as db:
        assert db.scalar(select(Decision.decision)) == 'Reviewed'
        assert db.scalar(select(func.count()).select_from(CompletionEvent)) == 1


def test_equal_counts_after_changed_decision_identity_reject_old_digest(committed_completion):
    app, factory, path, headers, cookies, review = committed_completion
    rid = review['recommendations'][0]['id']
    with TestClient(app, base_url='https://testserver', cookies=cookies) as client:
        client.headers['Origin'] = 'https://testserver'
        for decision in ('Deferred', 'Reviewed'):
            assert client.post(path + '/testing/completion/decisions', headers=headers,
                               json={'recommendation_id': rid, 'decision': decision}).status_code == 200
        current = client.get(path + '/testing/completion').json()
        assert current['ready'] and current['summary'] == review['summary']
        assert current['snapshot_digest'] != review['snapshot_digest']
        assert post(client, path, headers, review).status_code == 409
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(CompletionEvent)) == 0
        assert db.scalar(select(Assessment.status)) == 'Testing'


@pytest.fixture
def active_worker(scheduling_concurrency, monkeypatch, tmp_path):
    app, factory, *_ = scheduling_concurrency
    backend = Path(__file__).resolve().parents[1]
    config = Config(str(backend / 'alembic.ini'))
    config.set_main_option('script_location', str(backend / 'migrations'))
    command.upgrade(config, '0022')
    with factory() as db, TestClient(app, base_url='https://testserver') as client:
        client.headers['Origin'] = 'https://testserver'
        path, headers, _ = prepared.__wrapped__(client, db, monkeypatch)
        start = confirm(client, path, headers, get_review(client, path)['start_review'])
        assert start.status_code == 201
        identifier = UUID(start.json()['queued_execution_ids'][0])
        cookies = dict(client.cookies)
    entered, finish = Event(), Event()
    class PausedAdapter(FakeAdapter):
        def run(self, *args, **kwargs):
            outcome = super().run(*args, **kwargs)
            entered.set()
            if not finish.wait(timeout=15):
                raise RuntimeError('Synthetic worker release timed out')
            return outcome
    tmp_path.chmod(0o700)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(ExecutionRunner(factory, PausedAdapter(), EvidenceStore(tmp_path), 'competing-fixture').run, identifier)
        try:
            assert entered.wait(timeout=10)
            yield app, factory, path, headers, cookies, future, finish
        finally:
            finish.set()
            assert future.result(timeout=10)


def test_readiness_is_coherent_when_worker_finishes_after_select(active_worker):
    app, factory, path, headers, cookies, future, finish = active_worker
    engine = factory.kw['bind']
    changed = False
    def finish_after_select(conn, cursor, sql, *args):
        nonlocal changed
        if changed or 'json_agg' not in sql:
            return
        changed = True
        finish.set()
        assert future.result(timeout=10)
    event.listen(engine, 'after_cursor_execute', finish_after_select)
    try:
        with TestClient(app, base_url='https://testserver', cookies=cookies) as client:
            response = client.get(path + '/testing/completion')
    finally:
        event.remove(engine, 'after_cursor_execute', finish_after_select)
    assert changed and response.status_code == 200, response.text
    before = response.json()
    assert before['summary']['counts']['Running'] == 1
    assert before['summary']['active_attempts'] == before['summary']['active_execution_requests'] == 1
    assert before['summary']['recommendation_count'] == 0 and not before['ready']
    with TestClient(app, base_url='https://testserver', cookies=cookies) as client:
        client.headers['Origin'] = 'https://testserver'
        after = client.get(path + '/testing/completion').json()
        assert after['summary']['counts']['Completed'] == 1
        assert after['summary']['active_attempts'] == after['summary']['active_execution_requests'] == 0
        # Host reachability alone no longer fabricates a follow-up test.
        assert after['summary']['recommendation_count'] == 0 and after['ready']
        assert after['snapshot_digest'] != before['snapshot_digest']
        assert post(client, path, headers, before).status_code == 409


def test_completion_lock_prevents_worker_finishing_during_final_check(active_worker):
    app, factory, path, headers, cookies, future, finish = active_worker
    engine = factory.kw['bind']
    changed = False
    def after_parent_lock(conn, cursor, sql, *args):
        nonlocal changed
        if changed or 'FROM assessments' not in sql or 'FOR UPDATE' not in sql:
            return
        changed = True
        finish.set()
        with pytest.raises(TimeoutError):
            future.result(timeout=.2)
    with TestClient(app, base_url='https://testserver', cookies=cookies) as client:
        client.headers['Origin'] = 'https://testserver'
        prior = client.get(path + '/testing/completion').json()
        event.listen(engine, 'after_cursor_execute', after_parent_lock)
        try:
            result = post(client, path, headers, prior)
        finally:
            event.remove(engine, 'after_cursor_execute', after_parent_lock)
        assert changed and result.status_code == 409
    assert future.result(timeout=10)
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(CompletionEvent)) == 0
        assert db.scalar(select(Assessment.status)) == 'Testing'


def test_committed_completion_is_recovered_by_get_without_a_second_post(committed_completion):
    app, factory, path, headers, cookies, review = committed_completion
    with TestClient(app, base_url='https://testserver', cookies=cookies) as client:
        client.headers['Origin'] = 'https://testserver'
        # Model losing the initial HTTP receipt after the transaction committed.
        initial = post(client, path, headers, review)
        assert initial.status_code == 200
        recovered = client.get(path + '/testing/completion')
        assert recovered.status_code == 200
        assert recovered.json() == initial.json()
        assert recovered.json()['lifecycle_status'] == 'Finding Review'
        assert recovered.json()['completion']['snapshot_digest'] == review['snapshot_digest']
        assert recovered.headers['cache-control'] == 'no-store'
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(CompletionEvent)) == 1
        assert db.scalar(select(Assessment.status)) == 'Finding Review'
