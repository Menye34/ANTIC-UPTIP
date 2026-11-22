"""Recommended jobs never inherit assessment-start dispatch authorization."""
from types import SimpleNamespace

from app.recommended_test_consumer import dispatch_readiness, pending_ids
from app.nikto_profile import plan, PROFILE_ID, VERSION


def job(**overrides):
    values = dict(status='Queued', tool='Nikto', profile_id=PROFILE_ID,
                  profile_version=VERSION, execution_plan=plan('192.0.2.20', 80, 'http'))
    values.update(overrides)
    return SimpleNamespace(**values)


def test_release_policy_keeps_recommended_jobs_non_executable():
    assert dispatch_readiness(job(), boundary_enforced=True) is False
    assert dispatch_readiness(job(), boundary_enforced=False) is False


def test_rejects_changed_tool_profile_and_plan():
    assert not dispatch_readiness(job(tool='Nmap'), boundary_enforced=True)
    assert not dispatch_readiness(job(profile_version=VERSION + 1), boundary_enforced=True)
    assert not dispatch_readiness(job(execution_plan={'target': '192.0.2.20'}), boundary_enforced=True)
    assert not dispatch_readiness(job(status='Running'), boundary_enforced=True)
