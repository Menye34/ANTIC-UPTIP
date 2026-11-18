"""Read-only UI contracts against persisted synthetic data; no scanner calls."""
from hashlib import sha256
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select

from app.config import get_settings
from app.evidence_reading import EvidenceUnavailable, original_output
from app.models import BaselineExecutionRequest, AssessmentStartAuthorization, ExecutionAttempt, ExecutionEvent, ScannerEvidence, SecurityObservation
from test_scheduling_start import prepared, get_review, confirm  # noqa: F401
from test_execution_persistence import attempt_for, evidence_for, processing_for, observation_for


@pytest.fixture
def recorded(client, db, prepared):
    path, headers, owner = prepared
    receipt = confirm(client, path, headers, get_review(client, path)['start_review'])
    assert receipt.status_code == 201
    request = db.get(BaselineExecutionRequest, UUID(receipt.json()['queued_execution_ids'][0]))
    attempt = attempt_for(db, request)
    evidence = evidence_for(db, attempt)
    processing = processing_for(db, evidence)
    observation = observation_for(db, processing)
    db.flush()
    return path, request, evidence, observation


def test_persisted_recommendation_source_and_protected_original_output(client, db, recorded):
    path, request, evidence, observation = recorded
    tracked = (BaselineExecutionRequest, AssessmentStartAuthorization, ExecutionAttempt, ExecutionEvent, ScannerEvidence, SecurityObservation)
    rows_before = [db.scalar(select(func.count()).select_from(model)) for model in tracked]
    response = client.get(path + '/testing/recommendations')
    assert response.status_code == 200
    body = response.json()
    assert body['count'] == 1 and body['execution_authorized'] is False
    item = body['recommendations'][0]
    assert item['source_observation_id'] == str(observation.id)
    assert item['source_test'] == {'test_name': request.activity, 'tool': 'Nmap', 'status': 'Queued'}
    output_path = f'{path}/testing/executions/{request.id}/evidence/{evidence.id}/output'
    result = client.get(output_path)
    assert result.status_code == 200 and result.json()['content'] == evidence.content.decode()
    assert result.headers['cache-control'] == 'no-store'
    assert 'storage_key' not in result.text
    for suffix in ('eligibility', 'authorization-review'):
        check = client.get(path + '/testing/recommendations/' + item['id'] + '/' + suffix)
        assert check.status_code == 200
        assert check.json()['execution_available'] is False
        assert check.json()['authorization_available'] is False
    assert request.status == 'Queued'
    assert not db.new and not db.dirty and not db.deleted
    assert rows_before == [db.scalar(select(func.count()).select_from(model)) for model in tracked]
    assert client.get(output_path.replace(str(request.id), str(uuid4()))).status_code == 404
    assert client.get(output_path.replace(str(evidence.id), str(uuid4()))).status_code == 404
    assert client.get(output_path.replace(path, '/api/v1/assessments/' + str(uuid4()))).status_code == 404
    client.cookies.clear()
    assert client.get(output_path).status_code == 401


def test_other_analyst_cannot_read_output(client, db, recorded):
    from test_assessments import add_analyst, sign_in
    path, request, evidence, _ = recorded
    other = add_analyst(db, 'unassigned-evidence-reader')
    sign_in(client, other.username)
    assert client.get(f'{path}/testing/executions/{request.id}/evidence/{evidence.id}/output').status_code == 404
    assert client.get(path + '/testing/recommendations').status_code == 404


def row_for(content=b'<nmaprun/>', **changes):
    return SimpleNamespace(content=content, storage_key=None, size_bytes=len(content),
                           content_hash=sha256(content).hexdigest(), **changes)


def test_inline_integrity_and_size():
    row = row_for()
    assert original_output(row) == '<nmaprun/>'
    row.content_hash = '0' * 64
    with pytest.raises(EvidenceUnavailable): original_output(row)
    row.size_bytes = 10 * 1024 * 1024 + 1
    with pytest.raises(EvidenceUnavailable): original_output(row)
    row = row_for(b'\xff')
    with pytest.raises(EvidenceUnavailable): original_output(row)


def test_file_output_requires_private_secure_store(tmp_path):
    root = tmp_path / 'private'
    root.mkdir(mode=0o700)
    content = b'<script>inert scanner text</script>'
    name = 'a' * 32
    source = root / name
    source.write_bytes(content)
    source.chmod(0o600)
    row = row_for(content)
    row.content = None
    row.storage_key = 'evidence/' + name
    assert original_output(row, str(root)) == content.decode()
    with pytest.raises(EvidenceUnavailable): original_output(row)
    root.chmod(0o755)
    with pytest.raises(EvidenceUnavailable): original_output(row, str(root))
    root.chmod(0o700)
    for key in ('../secret', 'evidence/../../secret', '/etc/passwd', 'evidence/' + name + '/child'):
        row.storage_key = key
        with pytest.raises(EvidenceUnavailable): original_output(row, str(root))
    row.storage_key = 'evidence/' + name
    source.unlink()
    source.symlink_to(tmp_path / 'missing')
    with pytest.raises(EvidenceUnavailable): original_output(row, str(root))
    source.unlink()
    source.write_bytes(b'corrupted')
    source.chmod(0o600)
    with pytest.raises(EvidenceUnavailable): original_output(row, str(root))


def test_missing_private_file_has_safe_error(tmp_path):
    tmp_path.chmod(0o700)
    row = row_for()
    row.content = None
    row.storage_key = 'evidence/' + 'b' * 32
    with pytest.raises(EvidenceUnavailable) as caught:
        original_output(row, str(tmp_path))
    assert str(tmp_path) not in str(caught.value)


def test_private_file_endpoint_and_safe_rejection(client, db, recorded, tmp_path, monkeypatch, caplog):
    path, request, _, _ = recorded
    attempt = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.request_id == request.id))
    content = b'<nmaprun>synthetic-private-output</nmaprun>'
    root = tmp_path / 'private'
    root.mkdir(mode=0o700)
    name = 'c' * 32
    file = root / name
    file.write_bytes(content)
    file.chmod(0o600)
    source = evidence_for(db, attempt, content=None, storage_key='evidence/' + name,
                          size_bytes=len(content), content_hash=sha256(content).hexdigest(), format='nmap-xml')
    monkeypatch.setattr(get_settings(), 'evidence_read_directory', str(root))
    url = f'{path}/testing/executions/{request.id}/evidence/{source.id}/output'
    assert client.get(url).json()['content'] == content.decode()
    file.write_bytes(b'corrupted')
    rejected = client.get(url)
    assert rejected.status_code == 409
    assert 'synthetic-private-output' not in rejected.text + caplog.text
    assert str(root) not in rejected.text + caplog.text
    file.unlink()
    file.symlink_to(tmp_path / 'outside')
    assert client.get(url).status_code == 409
    file.unlink()
    assert client.get(url).status_code == 409
    monkeypatch.setattr(get_settings(), 'evidence_read_directory', None)
    assert client.get(url).status_code == 409


def test_oversized_output_rejected_before_file_access(client, db, recorded, monkeypatch):
    path, request, _, _ = recorded
    attempt = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.request_id == request.id))
    source = evidence_for(db, attempt, content=None, storage_key='evidence/' + 'd' * 32,
                          size_bytes=10 * 1024 * 1024 + 1, content_hash='0' * 64, format='nmap-xml')
    assert client.get(f'{path}/testing/executions/{request.id}/evidence/{source.id}/output').status_code == 409


def test_private_file_links_permissions_and_owner(tmp_path, monkeypatch):
    import os
    root = tmp_path / 'private'
    root.mkdir(mode=0o700)
    name = 'e' * 32
    file = root / name
    file.write_bytes(b'<nmaprun/>')
    file.chmod(0o600)
    row = row_for()
    row.content = None
    row.storage_key = 'evidence/' + name
    linked_root = tmp_path / 'linked-root'
    linked_root.symlink_to(root, target_is_directory=True)
    with pytest.raises(EvidenceUnavailable): original_output(row, str(linked_root))
    file.chmod(0o644)
    with pytest.raises(EvidenceUnavailable): original_output(row, str(root))
    file.chmod(0o600)
    extra = root / 'extra'
    os.link(file, extra)
    with pytest.raises(EvidenceUnavailable): original_output(row, str(root))
    extra.unlink()
    actual_uid = os.geteuid()
    monkeypatch.setattr(os, 'geteuid', lambda: actual_uid + 1)
    with pytest.raises(EvidenceUnavailable): original_output(row, str(root))


def test_existing_cross_assessment_and_cross_execution_evidence_denied(client, db, recorded):
    from app.models import Assessment, User
    from test_assessments import sign_in
    path, request, evidence, _ = recorded
    owner = db.get(User, db.get(Assessment, request.assessment_id).creator_id)
    headers = sign_in(client, owner.username)
    second = client.post('/api/v1/assessments', headers=headers, json={'name': 'Separate evidence assessment'})
    assert second.status_code == 201
    other = '/api/v1/assessments/' + second.json()['id']
    assert client.post(other + '/scope', headers=headers, json={'revision': 0, 'value': '192.0.2.0/24'}).status_code == 201
    assert client.post(other + '/targets', headers=headers, json={'value': '192.0.2.2'}).status_code == 201
    receipt = confirm(client, other, headers, get_review(client, other)['start_review'])
    assert receipt.status_code == 201
    other_execution = receipt.json()['queued_execution_ids'][0]
    # Both assessments and both executions genuinely exist and are readable by
    # this actor, but their evidence cannot be mixed.
    assert client.get(other + '/testing').status_code == 200
    assert client.get(f'{other}/testing/executions/{other_execution}/evidence/{evidence.id}/output').status_code == 404
    assert client.get(f'{other}/testing/executions/{request.id}/evidence/{evidence.id}/output').status_code == 404
    assert client.get(f'{path}/testing/executions/{other_execution}/evidence/{evidence.id}/output').status_code == 404
    assert client.get(other + '/testing/recommendations').json()['count'] == 0
    assert client.get(path + '/testing/recommendations').json()['count'] == 1
