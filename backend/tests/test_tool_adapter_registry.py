import pytest

from backend.app.nmap_adapter import AdapterConfig, NmapAdapter
from backend.app.nikto_adapter import NiktoAdapter, NiktoConfig
from backend.app.tool_adapter_registry import resolve_adapter


def test_registered_nmap_profiles_remain_supported():
    config = AdapterConfig('/usr/bin/nmap', 'a' * 64, '7.95')
    for profile in ('host-discovery', 'service-discovery'):
        adapter = resolve_adapter('Nmap', profile, config)
        assert type(adapter) is NmapAdapter
        assert adapter.config is config


def test_nikto_uses_same_registry_contract_without_launching():
    config = NiktoConfig('/usr/bin/nikto', 'b' * 64, '2.6.1')
    adapter = resolve_adapter('Nikto', 'nikto-http-service-restricted', config)
    assert type(adapter) is NiktoAdapter
    assert adapter.config is config


@pytest.mark.parametrize('tool,profile', [
    ('Nikto', 'host-discovery'), ('Nmap', 'nikto-http-service-restricted'),
    ('OWASP ZAP', 'web-scan'), ('Nikto', ''), ('nikto', 'nikto-http-service-restricted'),
])
def test_unregistered_pairs_fail_closed(tool, profile):
    with pytest.raises(ValueError, match='unsupported_tool_profile'):
        resolve_adapter(tool, profile, NiktoConfig('/usr/bin/nikto', 'b' * 64, '2.6.1'))


def test_cross_tool_config_is_rejected():
    with pytest.raises(ValueError, match='tool_configuration_mismatch'):
        resolve_adapter('Nikto', 'nikto-http-service-restricted', AdapterConfig('/usr/bin/nmap', 'a'*64, '7.95'))


def test_tool_adapters_are_independent_implementations():
    from backend.app.nmap_adapter import SupervisedToolAdapter
    assert issubclass(NmapAdapter, SupervisedToolAdapter)
    assert issubclass(NiktoAdapter, SupervisedToolAdapter)
    assert not issubclass(NiktoAdapter, NmapAdapter)
    assert not issubclass(NmapAdapter, NiktoAdapter)
