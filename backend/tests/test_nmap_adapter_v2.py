"""Controlled synthetic executables, never Nmap or network probes."""
import os
from pathlib import Path
import subprocess

import pytest

from app.dispatch_policy import plan
from app.nmap_adapter import AdapterConfig, AdapterUnavailable, NmapAdapter, verify_privileges


def fixture_adapter(tmp_path, monkeypatch, code, **limits):
    script = tmp_path/'synthetic-scanner'
    script.write_text('#!/usr/bin/python3\n'+code)
    script.chmod(0o700)
    config = AdapterConfig(str(script), 'a'*64, '7.95', **limits)
    adapter = NmapAdapter(config)
    # Bypass trust inspection ONLY for this explicitly synthetic test fixture.
    monkeypatch.setattr(adapter, '_open_executable', lambda: os.open(script, os.O_RDONLY))
    return adapter


def test_controlled_subprocess_exact_arguments(tmp_path, monkeypatch):
    adapter = fixture_adapter(tmp_path, monkeypatch,
        "import sys\nassert sys.argv[1:]==['-sn','-n','-oX','-','192.0.2.1']\nprint('synthetic-output')\n")
    identities = []
    result = adapter.run(plan('192.0.2.1'), safe=lambda: True, launched=identities.append)
    assert result.exit_code == 0 and result.terminated and not result.partial
    assert result.stdout == b'synthetic-output\n' and len(identities) == 1


def test_controlled_subprocess_timeout(tmp_path, monkeypatch):
    adapter = fixture_adapter(tmp_path, monkeypatch, 'import time\ntime.sleep(20)\n', timeout=1)
    result = adapter.run(plan('192.0.2.1'), safe=lambda: True, launched=lambda _: None)
    assert result.terminated and result.partial and result.reason == 'execution_timeout'


def test_controlled_subprocess_output_limit(tmp_path, monkeypatch):
    adapter = fixture_adapter(tmp_path, monkeypatch,
        "import sys\nsys.stdout.write('x'*20000)\nsys.stdout.flush()\n", output_limit=1000)
    result = adapter.run(plan('192.0.2.1'), safe=lambda: True, launched=lambda _: None)
    assert len(result.stdout) <= 1000 and result.partial and result.terminated
    assert result.reason == 'output_limit_exceeded'


def test_authorization_loss_stops_synthetic_process(tmp_path, monkeypatch):
    adapter = fixture_adapter(tmp_path, monkeypatch, 'import time\ntime.sleep(20)\n')
    checks = iter((True, False))
    result = adapter.run(plan('192.0.2.1'), safe=lambda: next(checks, False), launched=lambda _: None)
    assert result.terminated and result.partial and result.reason == 'runtime_safety_lost'


def test_prelaunch_denial_never_spawns(tmp_path, monkeypatch):
    adapter = fixture_adapter(tmp_path, monkeypatch, 'raise AssertionError()\n')
    def forbidden(*args, **kwargs):
        raise AssertionError('Should not launch')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    with pytest.raises(AdapterUnavailable, match='authorization'):
        adapter.run(plan('192.0.2.1'), safe=lambda: False, launched=lambda _: None)


def test_root_and_privileged_environment_rejected(monkeypatch):
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    with pytest.raises(AdapterUnavailable):
        verify_privileges()


def test_untrusted_executable_is_rejected(tmp_path):
    adapter = NmapAdapter(AdapterConfig(str(tmp_path/'missing'), 'a'*64, '7.95'))
    with pytest.raises((AdapterUnavailable, FileNotFoundError)):
        adapter.verify()


def test_executable_hash_mismatch_is_rejected():
    # Inspect Python as a harmless root-owned ELF fixture; never invoke it here.
    binary = str(Path('/usr/bin/python3').resolve())
    adapter = NmapAdapter(AdapterConfig(binary, 'a'*64, '7.95'))
    with pytest.raises(AdapterUnavailable):
        adapter._open_executable()


def test_unconfirmed_termination_is_not_success(monkeypatch):
    class Unkillable:
        pid = 123
        def wait(self, timeout):
            raise subprocess.TimeoutExpired('synthetic', timeout)
        def poll(self):
            return None
    monkeypatch.setattr(os, 'killpg', lambda *_: None)
    assert NmapAdapter._stop(Unkillable()) is False
