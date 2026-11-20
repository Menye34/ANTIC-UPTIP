"""Actual Phase 3 API composition on disposable data; fake scanner only."""
from pathlib import Path
from uuid import UUID

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import func, inspect, select, text

from app.models import (Assessment, BaselineExecutionRequest, ExecutionAttempt,
                        RecommendationAuthorizationRecord, RecommendationExecutionRequest,
                        ScannerEvidence, SecurityObservation)
from test_testing_completion_contract import completed_work  # noqa: F401
from test_scheduling_start import prepared, scheduling_concurrency  # noqa: F401


def test_persisted_recommendation_checks_are_read_only_and_decisions_sync(client, db, completed_work):
    path, headers, _, request_id = completed_work
    models = (BaselineExecutionRequest, ExecutionAttempt, ScannerEvidence, SecurityObservation,
              RecommendationAuthorizationRecord, RecommendationExecutionRequest)
    counts = lambda: [db.scalar(select(func.count()).select_from(model)) for model in models]
    before = counts()
    listing = client.get(path + '/testing/recommendations')
    assert listing.status_code == 200, listing.text
    body = listing.json()
    assert body['count'] == 1 and body['recommendations'][0]['decision'] is None
    item = body['recommendations'][0]
    assert item['source_test']['status'] == 'Completed'
    for endpoint in ('eligibility', 'authorization-review'):
        response = client.get(path + '/testing/recommendations/' + item['id'] + '/' + endpoint)
        assert response.status_code == 200, response.text
        assert response.headers['cache-control'] == 'no-store'
        result = response.json()
        assert result['reason_code'] == 'tool_integration_pending'
        assert not result['eligible'] and not result['authorization_available'] and not result['execution_available']
    assert counts() == before
    decision_path = path + '/testing/completion/decisions'
    payload = {'recommendation_id': item['id'], 'decision': 'Deferred'}
    assert client.post(decision_path, json=payload).status_code == 403
    assert client.post(decision_path, headers=headers, json=payload).status_code == 200
    updated = client.get(path + '/testing/recommendations').json()
    review = client.get(path + '/testing/completion').json()
    assert updated['recommendations'][0]['decision'] == 'Deferred'
    assert updated['decision_counts'] == review['summary']['decision_counts']
    assert not review['ready'] and 'pending_recommendations' in review['summary']['blockers']
    assert counts() == before
    assert db.get(BaselineExecutionRequest, request_id).status == 'Completed'
    assert db.get(Assessment, UUID(path.rsplit('/', 1)[1])).status == 'Testing'


@pytest.mark.parametrize('scheduling_concurrency', ['migration_0017'], indirect=True)
def test_phase3_migration_chain_preserves_existing_assessment(scheduling_concurrency):
    _, factory, prepared_data, _, _ = scheduling_concurrency
    identifier = UUID(prepared_data[0].rsplit('/', 1)[1])
    config = Config(str(Path(__file__).resolve().parents[1] / 'alembic.ini'))
    config.set_main_option('script_location', str(Path(__file__).resolve().parents[1] / 'migrations'))
    for revision in ('0019', '0020', '0021', '0022', '0023'):
        command.upgrade(config, revision)
        with factory() as db:
            assert db.scalar(text('SELECT version_num FROM alembic_version')) == revision
            assert db.get(Assessment, identifier).status == 'Draft'
    with factory() as db:
        from alembic.autogenerate import compare_metadata
        from alembic.migration import MigrationContext
        from app.database import Base
        assert compare_metadata(MigrationContext.configure(db.connection()), Base.metadata) == []
        schema = inspect(db.connection())
        for table in ('recommendation_authorization_records', 'recommendation_execution_requests',
                      'testing_recommendation_decisions', 'testing_completion_events'):
            assert schema.has_table(table)
            assert schema.get_foreign_keys(table)
        names = set(db.scalars(text("SELECT tgname FROM pg_trigger WHERE NOT tgisinternal")))
        assert {'immutable_testing_completion', 'no_testing_completion_truncate',
                'no_testing_decision_delete', 'protect_completed_testing_state'} <= names


def test_recommendation_routes_reject_cross_assessment_access(client, db, completed_work):
    from test_assessments import add_analyst, sign_in
    path, _, _, _ = completed_work
    item = client.get(path + '/testing/recommendations').json()['recommendations'][0]
    endpoints = ('/testing/recommendations', '/testing/recommendations/' + item['id'] + '/eligibility',
                 '/testing/recommendations/' + item['id'] + '/authorization-review', '/testing/completion')
    client.cookies.clear()
    for endpoint in endpoints:
        assert client.get(path + endpoint).status_code == 401
    other = add_analyst(db, 'phase3-unassigned-analyst')
    headers = sign_in(client, other.username)
    for endpoint in endpoints:
        assert client.get(path + endpoint).status_code == 404
    denied = client.post(path + '/testing/completion/decisions', headers=headers,
        json={'recommendation_id': item['id'], 'decision': 'Reviewed'})
    assert denied.status_code == 404
