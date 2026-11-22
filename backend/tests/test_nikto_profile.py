"""The new Nikto profile is inert until separately authorized dispatch exists."""
import pytest
from app.nikto_profile import authority, plan, validate_plan


def test_restricted_profile_is_non_dispatchable():
    profile = authority()
    assert profile['tool'] == 'Nikto'
    assert profile['execution_enabled'] is False
    assert profile['network_boundary'] == 'exact_ipv4_tcp_endpoint'
    assert profile['redirects'] == profile['dns'] == profile['proxies'] == 'deny'


def test_canonical_endpoint_preview_and_digest():
    item = plan('192.0.2.20', 8000, 'http')
    assert item['endpoint_preview'] == 'http://192.0.2.20:8000/'
    assert validate_plan(item)
    assert not validate_plan({**item, 'port': 8001})
    assert not validate_plan({**item, 'parameter_digest': '0' * 64})


@pytest.mark.parametrize('target,port,scheme', [
    ('example.com', 80, 'http'), ('192.0.002.1', 80, 'http'),
    ('2001:db8::1', 80, 'http'), ('0.0.0.0', 80, 'http'),
    ('224.0.0.1', 80, 'http'), ('192.0.2.20', 0, 'http'),
    ('192.0.2.20', True, 'http'), ('192.0.2.20', 65536, 'http'),
    ('192.0.2.20', 80, 'ftp'), ('192.0.2.20', 80, 'HTTP'),
])
def test_invalid_endpoint_is_rejected(target, port, scheme):
    with pytest.raises(ValueError):
        plan(target, port, scheme)
