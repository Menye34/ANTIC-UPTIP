from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

from app.target_scope import classify
from test_assessments import API, add_analyst, sign_in


@pytest.mark.parametrize('value,kind,boundary,boundary_kind,expected', [
    ('192.0.2.4', 'IP address', '192.0.2.0/24', 'Subnet', 'in_scope'),
    ('192.0.2.0/25', 'Subnet', '192.0.2.0/24', 'Subnet', 'in_scope'),
    ('192.0.2.0/24', 'Subnet', '192.0.2.0/25', 'Subnet', 'out_of_scope'),
    ('192.0.2.4/32', 'Subnet', '192.0.2.4', 'IP address', 'out_of_scope'),
    ('a.example.test', 'Hostname', 'example.test', 'Hostname', 'out_of_scope'),
    ('https://example.test/a', 'Web URL', 'example.test', 'Hostname', 'out_of_scope'),
    ('https://example.test/a/b', 'Web URL', 'https://example.test/a', 'Web URL', 'out_of_scope'),
    ('https://example.test/a', 'Web URL', 'https://example.test/a', 'Web URL', 'in_scope'),
    ('example.test', 'Hostname', 'https://example.test/', 'Web URL', 'out_of_scope'),
])
def test_conservative_scope_matching(value, kind, boundary, boundary_kind, expected):
    assert classify(value, kind, [(boundary, boundary_kind)])[0] == expected


def test_target_lifecycle_and_scope_reclassification(client, db):
    owner = add_analyst(db, 'target-owner')
    headers = sign_in(client, owner.username)
    assessment = client.post(API, headers=headers, json={'name': 'Target assessment'}).json()
    parent = f"{API}/{assessment['id']}"
    targets = parent + '/targets'
    scope = parent + '/scope'
    assert client.get(targets).json()['counts'] == {'total': 0, 'blocked': 0, 'eligible': 0}
    assert client.post(targets, json={'value': '256.0.0.1'}, headers=headers).status_code == 422
    assert client.post(targets, json={'value': '192.0.2.4'}).status_code == 403
    assert client.post(targets, json={'value': '192.0.2.4'}, headers={**headers, 'Origin': 'https://other.test'}).status_code == 403
    response = client.post(targets, json={'value': ' 192.0.2.4 '}, headers=headers)
    assert response.status_code == 201
    entry = response.json()['targets'][0]
    assert entry['original_value'] == ' 192.0.2.4 '
    assert entry['normalized_value'] == '192.0.2.4'
    assert entry['eligibility'] == 'blocked'
    assert client.post(targets, json={'value': '192.0.2.4'}, headers=headers).status_code == 409
    assert client.get(parent).json()['target_count'] == 1

    boundary = client.post(scope, json={'value': '192.0.2.0/24', 'revision': 0}, headers=headers).json()
    assert boundary['affected_target_count'] == 1
    view = client.get(targets).json()
    assert view['targets'][0]['eligibility'] == 'pending' and view['counts']['eligible'] == 0
    assert view['targets'][0]['scope_revision'] == 1

    extra = client.post(scope, json={'value': 'unrelated.test', 'revision': 1}, headers=headers).json()
    assert extra['affected_target_count'] == 0
    deleted = client.request('DELETE', scope + '/' + boundary['entries'][0]['id'],
                             json={'confirmed': True, 'revision': 2}, headers=headers).json()
    assert deleted['affected_target_count'] == 1
    view = client.get(targets).json()
    assert view['targets'][0]['id'] == entry['id']
    assert view['targets'][0]['scope_revision'] == 3 and view['counts']['blocked'] == 1

    other = client.post(API, headers={**headers, 'Idempotency-Key': str(uuid4())}, json={'name': 'Other'}).json()
    assert client.patch(f"{API}/{other['id']}/targets/{entry['id']}", json={'value': 'test.example', 'revision': 1},
                        headers=headers).status_code == 404
    entry_path = targets + '/' + entry['id']
    edited = client.patch(entry_path, json={'value': 'HTTPS://Example.TEST:8443/a?x=Y', 'revision': 1},
                          headers=headers).json()['targets'][0]
    assert edited['normalized_value'] == 'https://example.test:8443/a?x=Y'
    assert edited['kind'] == 'Web URL' and edited['revision'] == 2
    assert client.request('DELETE', entry_path, json={'confirmed': True, 'revision': 1}, headers=headers).status_code == 409
    assert client.request('DELETE', entry_path, json={'confirmed': False, 'revision': 2}, headers=headers).status_code == 422
    assert client.request('DELETE', entry_path, json={'confirmed': True, 'revision': 2}, headers=headers).json()['targets'] == []

    outsider = add_analyst(db, 'target-outsider')
    headers = sign_in(client, outsider.username)
    assert client.get(targets).status_code == 404
    assert client.post(targets, json={'value': '192.0.2.4'}, headers=headers).status_code == 404


def test_concurrent_normalized_duplicates_create_one_target(client, db):
    owner = add_analyst(db, 'concurrent-target-owner')
    headers = sign_in(client, owner.username)
    assessment = client.post(API, headers=headers, json={'name': 'Concurrent targets'}).json()
    path = f"{API}/{assessment['id']}/targets"
    cookies = dict(client.cookies)
    barrier = Barrier(2, timeout=10)

    def submit(value):
        with TestClient(create_app(), base_url='https://testserver', cookies=cookies) as worker:
            barrier.wait()
            return worker.post(path, json={'value': value}, headers={**headers, 'Origin': 'https://testserver'})

    with ThreadPoolExecutor(max_workers=2) as workers:
        responses = list(workers.map(submit, ['Example.test', ' example.test ']))
    assert sorted(response.status_code for response in responses) == [201, 409]
    assert client.get(path).json()['counts'] == {'total': 1, 'eligible': 0, 'blocked': 1}
