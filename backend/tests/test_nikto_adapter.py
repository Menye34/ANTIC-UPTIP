import pytest
from backend.app.nikto_adapter import NiktoAdapter, NiktoConfig
from backend.app.nmap_adapter import AdapterUnavailable
from backend.app.nikto_profile import plan


def config():
    return NiktoConfig('/usr/bin/nikto', 'a'*64, '2.5.0')


def test_reuses_shared_process_supervisor_without_inheriting_nmap_adapter():
    from backend.app.nmap_adapter import NmapAdapter, SupervisedToolAdapter
    assert issubclass(NiktoAdapter, SupervisedToolAdapter)
    assert not issubclass(NiktoAdapter, NmapAdapter)
    adapter = NiktoAdapter(config())
    assert adapter.validate_execution_plan(plan('192.0.2.10', 8000, 'http'))
    assert adapter.command(plan('192.0.2.10', 8000, 'http'), False) == [
        '/usr/bin/nikto', '-host', '192.0.2.10', '-port', '8000',
        '-nointeractive', '-noupdate', '-nolookup', '-noredirect',
        '-timeout', '10s', '-maxtime', '300s']
    assert adapter.command(plan('192.0.2.10', 443, 'https'), False)[-1] == '-ssl'
    assert not any('PROXY' in k.upper() for k in adapter.environment())


def test_rejects_invalid_plans_and_config():
    adapter = NiktoAdapter(config())
    with pytest.raises(AdapterUnavailable):
        adapter.command({'target': 'example.com'}, False)
    for version in ('2.5.0;whoami', '7.95', ''):
        with pytest.raises(AdapterUnavailable):
            NiktoConfig('/usr/bin/nikto', 'a'*64, version)
