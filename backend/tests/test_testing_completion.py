"""Completion readiness must fail closed and never transition while work is active."""
from uuid import UUID
from sqlalchemy import select
from app.models import Assessment, BaselineExecutionRequest, TestingCompletionEvent
from test_scheduling_start import prepared, get_review, confirm


def test_completion_blocks_queued_baseline(client, db, prepared):
    path, headers, _ = prepared
    assert confirm(client, path, headers, get_review(client, path)['start_review']).status_code == 201
    review = client.get(path + '/testing/completion')
    assert review.status_code == 200
    body = review.json()
    assert body['ready'] is False
    assert 'active_tests' in body['summary']['blockers']
    denied = client.post(path + '/testing/completion', headers=headers, json={
        'snapshot_digest': body['snapshot_digest'], 'confirmed': True})
    assert denied.status_code == 409
    assessment_id = UUID(path.rsplit('/', 1)[-1])
    db.expire_all()
    assert db.get(Assessment, assessment_id).status == 'Testing'
    assert db.get(TestingCompletionEvent, assessment_id) is None


def test_completion_rejects_stale_digest_and_missing_csrf(client, db, prepared):
    path, headers, _ = prepared
    assert confirm(client, path, headers, get_review(client, path)['start_review']).status_code == 201
    bad = client.post(path + '/testing/completion', json={
        'snapshot_digest': '0' * 64, 'confirmed': True})
    assert bad.status_code in (401, 403)
    stale = client.post(path + '/testing/completion', headers=headers, json={
        'snapshot_digest': '0' * 64, 'confirmed': True})
    assert stale.status_code == 409


def test_completion_decision_rejects_unknown_recommendation(client, db, prepared):
    path, headers, _ = prepared
    assert confirm(client, path, headers, get_review(client, path)['start_review']).status_code == 201
    response = client.post(path + '/testing/completion/decisions', headers=headers,
        json={'recommendation_id': '0' * 64, 'decision': 'Reviewed'})
    assert response.status_code == 409
