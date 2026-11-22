"""Deployment configuration is simulated; no scanner or live activation."""
from copy import deepcopy
from types import SimpleNamespace
import subprocess
from pathlib import Path
import pytest
from app import nikto_profile as profile
from app.nikto_adapter import NiktoAdapter, NiktoConfig
from app.nmap_adapter import AdapterUnavailable, ScanOutcome


@pytest.fixture
def config(monkeypatch):
    from app import config as module
    settings=SimpleNamespace(nikto_policy_version=None,nikto_policy_digest=None,nikto_policy_approval_reference=None)
    monkeypatch.setattr(module,'get_settings',lambda:settings)
    return settings


def approve(settings):
    settings.nikto_policy_version=2
    settings.nikto_policy_digest=profile.authority(2)['digest']
    settings.nikto_policy_approval_reference='local-acceptance-ticket-123'


def test_disabled_historical_definition_and_digest_are_preserved(config):
    assert profile.authority(1)['digest']=='0697d4df027f87e68d7d9c8447dcbc4e8f4cbfd77d75ee4c19241b12fd474729'
    assert not profile.authority(1)['execution_enabled']
    assert not profile.dispatch_enabled(profile.plan('192.0.2.1',8080,'http',version=2))
    approve(config)
    assert profile.authority(1)['execution_enabled'] is False
    assert not profile.dispatch_enabled(profile.plan('192.0.2.1',8080,'http'))


def test_v2_requires_exact_explicit_operator_configuration(config):
    approve(config)
    candidate=profile.plan('192.0.2.1',8080,'http',version=2)
    assert profile.validate_plan(candidate) and profile.dispatch_enabled(candidate)
    assert profile.activation()['approval_reference']=='local-acceptance-ticket-123'
    for field,value in (('port',8081),('policy_digest','0'*64),('profile_version',1),('parameter_digest','0'*64)):
        assert not profile.dispatch_enabled({**candidate,field:value})
    config.nikto_policy_approval_reference=None
    assert not profile.dispatch_enabled(candidate)


@pytest.mark.parametrize('field,value',[
    ('nikto_policy_version',None),('nikto_policy_version',1),('nikto_policy_version',999),
    ('nikto_policy_digest',None),('nikto_policy_digest','0'*64),('nikto_policy_digest','é'*64),
    ('nikto_policy_approval_reference',None),('nikto_policy_approval_reference',''),
    ('nikto_policy_approval_reference','approval\nforged-log'),
])
def test_partial_invalid_or_mismatched_approval_is_denied(config,field,value):
    approve(config);setattr(config,field,value)
    with pytest.raises(ValueError):profile.activation()
    assert not profile.dispatch_enabled(profile.plan('192.0.2.1',8080,'http',version=2))


def test_mutated_release_policy_cannot_be_activated(config,monkeypatch):
    approve(config)
    monkeypatch.setitem(profile.POLICY_V2,'max_processes',2)
    with pytest.raises(ValueError,match='integrity'):profile.activation()


def test_v2_arguments_are_release_owned_and_v1_plans_not_rewritten(config):
    old=profile.plan('192.0.2.1',8080,'http');saved=deepcopy(old)
    approve(config)
    new=profile.plan('192.0.2.1',8080,'http',version=2)
    adapter=NiktoAdapter(NiktoConfig('/usr/bin/nikto','a'*64,'2.6.1'))
    argv=adapter.command(new,False)
    assert argv[5:]==profile.authority(2)['fixed_arguments']
    assert '-followredirects' not in argv and '-useproxy' not in argv
    assert old==saved and old['policy_digest']!=new['policy_digest']
    with pytest.raises(ValueError):profile.plan('192.0.2.1',8080,'http',version=999)


def test_missing_nikto_never_launches(monkeypatch):
    adapter=NiktoAdapter(NiktoConfig('/nonexistent/nikto','a'*64,'2.6.1'))
    def forbidden(*args,**kwargs):raise AssertionError('must not spawn')
    monkeypatch.setattr(subprocess,'Popen',forbidden)
    with pytest.raises(AdapterUnavailable):adapter.verify()


def test_unmatched_version_or_partial_probe_is_rejected(monkeypatch):
    adapter=NiktoAdapter(NiktoConfig('/usr/bin/nikto','a'*64,'2.6.1'))
    for outcome in (ScanOutcome(b'Nikto v2.5.0',b'',0,'scanner_exited',True,False),
                    ScanOutcome(b'Nikto v2.6.1',b'',0,'scanner_exited',True,True)):
        monkeypatch.setattr(adapter,'run',lambda *args,**kwargs:outcome)
        with pytest.raises(AdapterUnavailable,match='version'):adapter.verify()


def test_worker_requires_all_three_optional_nikto_pins_together(monkeypatch):
    from app import execution_worker
    def forbidden(*args,**kwargs):raise AssertionError('must not access database or probe scanner')
    monkeypatch.setattr(execution_worker,'get_settings',forbidden)
    monkeypatch.setattr(execution_worker,'resolve_adapter',lambda *a,**kw:object())
    args=['--executable','/usr/bin/nmap','--sha256','a'*64,'--version','7.99',
          '--evidence-directory','/nonexistent','--enable-dispatch','--nikto-executable','/usr/bin/nikto']
    with pytest.raises(SystemExit) as error:execution_worker.main(args)
    assert error.value.code==2


def test_optional_dropin_preserves_nmap_and_does_not_change_worker_identity():
    text=(Path(__file__).resolve().parents[2]/'deploy/systemd/uptip-execution-worker-nikto.conf.example').read_text()
    assert '\nExecStart=\n' in text
    for key in ('NMAP_EXECUTABLE','NMAP_SHA256','NMAP_VERSION','EVIDENCE_DIRECTORY',
                'NIKTO_EXECUTABLE','NIKTO_SHA256','NIKTO_VERSION'):
        assert '${UPTIP_'+key+'}' in text
    assert 'User=' not in text and 'Group=' not in text and 'Environment=' not in text


def test_nikto_hash_mismatch_never_invokes_scanner(tmp_path,monkeypatch):
    import os
    import app.nmap_adapter as module
    executable=tmp_path/'synthetic-entry';executable.write_bytes(b'controlled non-executable-content fixture');executable.chmod(0o700)
    # Only model trust ownership for a synthetic local fixture, never a scanner.
    original_stat,original_fstat=module.Path.stat,module.os.fstat
    def owned(info):
        values=list(info);values[4]=0;return os.stat_result(values)
    monkeypatch.setattr(module,'verify_privileges',lambda:None)
    monkeypatch.setattr(module.Path,'stat',lambda self,*a,**kw:owned(original_stat(self,*a,**kw)))
    monkeypatch.setattr(module.os,'fstat',lambda fd:owned(original_fstat(fd)))
    def forbidden(*args,**kwargs):raise AssertionError('must not launch')
    monkeypatch.setattr(subprocess,'Popen',forbidden)
    adapter=NiktoAdapter(NiktoConfig(str(executable),'0'*64,'2.6.1'))
    with pytest.raises(AdapterUnavailable,match='digest_mismatch'):adapter.verify()


def test_invalid_optional_nikto_configuration_does_not_disable_nmap(monkeypatch,tmp_path,capsys):
    from app import execution_worker as worker
    verified=[]
    class FakeNmap:
        def verify(self):verified.append('Nmap')
    class DatabaseBoundaryReached(Exception):pass
    monkeypatch.setattr(worker,'resolve_adapter',lambda tool,*a:FakeNmap() if tool=='Nmap' else pytest.fail('unsupported Nikto must be rejected before adapter creation'))
    monkeypatch.setattr(worker,'EvidenceStore',lambda *a:object())
    monkeypatch.setattr(worker.signal,'signal',lambda *a:None)
    monkeypatch.setattr(worker,'get_settings',lambda:SimpleNamespace(database_url='postgresql+psycopg://unused'))
    def stopped(*args,**kwargs):raise DatabaseBoundaryReached()
    monkeypatch.setattr(worker,'create_engine',stopped)
    args=['--executable','/usr/bin/nmap','--sha256','a'*64,'--version','7.99',
          '--evidence-directory',str(tmp_path),'--enable-dispatch','--nikto-executable','/usr/bin/nikto',
          '--nikto-sha256','a'*64,'--nikto-version','2.5.0']
    with pytest.raises(DatabaseBoundaryReached):worker.main(args)
    assert verified==['Nmap']
    assert 'uptip_nikto_unavailable' in capsys.readouterr().out



@pytest.mark.parametrize('label',[b'Nikto 2.6.1 (LW 2.5)',b'- Nikto v2.6.1 (LW 2.5)',b'Nikto version 2.6.1'])
def test_exact_installed_version_banner_formats(label,monkeypatch):
    adapter=NiktoAdapter(NiktoConfig('/usr/bin/nikto','a'*64,'2.6.1'))
    monkeypatch.setattr(adapter,'run',lambda *a,**kw:ScanOutcome(label,b'',0,'scanner_exited',True,False))
    adapter.verify()
