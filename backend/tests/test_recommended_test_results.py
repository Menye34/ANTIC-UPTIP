from types import SimpleNamespace
import pytest
from app.recommended_test_results import mark_running, record_outcome


def job(status='Queued'):
    return SimpleNamespace(status=status)


def outcome(**overrides):
    data = dict(stdout=b'Nikto output', stderr=b'', exit_code=0,
                reason='scanner_exited', terminated=True, partial=False)
    data.update(overrides)
    return SimpleNamespace(**data)


def test_queued_running_completed_and_bounded_original_output():
    item = job()
    mark_running(item)
    assert item.status == 'Running' and item.started_at
    assert record_outcome(item, outcome()) == 'Completed'
    assert item.stdout == b'Nikto output' and len(item.output_digest) == 64
    assert item.finished_at and item.failure_reason is None


def test_failed_scan_retains_original_output():
    item = job()
    mark_running(item)
    assert record_outcome(item, outcome(exit_code=1, reason='scanner_exited', partial=True)) == 'Failed'
    assert item.stdout == b'Nikto output'


def test_invalid_transitions_and_oversize_output_rejected():
    with pytest.raises(ValueError):
        mark_running(job('Completed'))
    with pytest.raises(ValueError):
        record_outcome(job(), outcome())
    item = job()
    mark_running(item)
    with pytest.raises(ValueError):
        record_outcome(item, outcome(stdout=b'x' * (5 * 1024 * 1024 + 1)))
    assert item.status == 'Running'
