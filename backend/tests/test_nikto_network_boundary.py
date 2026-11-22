"""Containment unit checks plus explicit opt-in, local-only Kali kernel acceptance."""
import ctypes.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import pytest
from app.nikto_network_boundary import NamespaceBoundary, rules, TOOLS, trusted_tool
from app.nmap_adapter import AdapterUnavailable
from app.nikto_adapter import NiktoAdapter, NiktoConfig
from app.nikto_profile import plan


@pytest.mark.parametrize('target,port', [('example.com',80),('127.0.0.1',80),('10.0.2.2',80),('0.0.0.0',80),('224.0.0.1',80),('192.0.2.1',53),('192.0.2.1',True),('192.0.2.1',65536)])
def test_boundary_refuses_ambiguous_endpoints(target,port):
    with pytest.raises(ValueError): rules(target,port)


def test_nft_rules_allow_only_exact_ipv4_tcp_and_deny_all_else():
    script = rules('192.0.2.1',8080)
    assert script.count('policy drop') == 3
    assert 'ip daddr 192.0.2.1 tcp dport 8080 accept;' in script
    assert script.count('meta nfproto ipv6 drop') == 2
    assert 'udp' not in script and 'dport 53' not in script
    assert 'daddr' not in rules(None,None)


def test_adapter_cannot_launch_without_an_active_matching_boundary(monkeypatch):
    boundary = NamespaceBoundary()
    adapter = NiktoAdapter(NiktoConfig('/usr/bin/nikto','a'*64,'2.6.1'), boundary=boundary)
    with pytest.raises(AdapterUnavailable,match='network_boundary_required'):
        adapter.launch_context(plan('192.0.2.1',8080,'http'),False)
    with pytest.raises(AdapterUnavailable,match='network_boundary_required'):
        NiktoAdapter(adapter.config).launch_context(None,True)
    assert not boundary.enforced


def test_missing_or_untrusted_helpers_fail_before_any_scanner_or_namespace_launch(monkeypatch):
    import app.nikto_network_boundary as module
    def deny(*args): raise AdapterUnavailable('untrusted_isolation_tool')
    def forbidden(*args,**kwargs): raise AssertionError('must not launch')
    monkeypatch.setattr(module,'trusted_tool',deny)
    monkeypatch.setattr(subprocess,'Popen',forbidden)
    boundary = NamespaceBoundary()
    with pytest.raises(AdapterUnavailable):
        with boundary.restrict('192.0.2.1',8080): pass
    assert not boundary.enforced and boundary._fds == ()


@pytest.mark.parametrize('scenario', ['allowed','other_port','other_ip','dns','ipv6','firewall','escape','readonly','parent'])
def test_kali_kernel_containment(scenario):
    """No public target: explicit opt-in must name an address this host can bind.

    Not a real Nikto scan. Exercises the exact child namespace/capability/seccomp
    hook used by Nikto against two short-lived local listening sockets.
    """
    if os.environ.get('UPTIP_NIKTO_CONTAINMENT_TEST') != '1':
        pytest.skip('Requires explicit Kali local containment acceptance and nft/slirp4netns')
    address = os.environ.get('UPTIP_AUTHORIZED_TEST_IPV4')
    if not address: pytest.fail('Set UPTIP_AUTHORIZED_TEST_IPV4 to an authorized non-loopback address of this host')
    from ipaddress import IPv4Address
    assert IPv4Address(address).is_private and not IPv4Address(address).is_loopback
    for path in TOOLS.values(): trusted_tool(path)
    assert ctypes.util.find_library('seccomp')
    sockets = []
    temporary = tempfile.TemporaryDirectory(prefix='uptip-nikto-containment-')
    probe = Path(temporary.name) / 'readonly-probe'
    probe.write_text('')
    try:
        for _ in range(2):
            listener = socket.socket(); listener.bind((address,0)); listener.listen(8); sockets.append(listener)
        port, other = [s.getsockname()[1] for s in sockets]
        before = os.readlink('/proc/self/ns/net')
        boundary = NamespaceBoundary()
        with boundary.restrict(address,port):
            if scenario == 'parent':
                assert os.readlink('/proc/self/ns/net') == before
                with socket.create_connection((address,other),timeout=1): pass
                return
            params = {'address':address,'port':port,'other':other,'scenario':scenario,'probe':str(probe)}
            code = '''import socket,os,json,ctypes,subprocess
p=json.loads(os.environ['UPTIP_TEST_PROBE'])
kind=p['scenario']
ok=False
try:
 if kind in ('allowed','other_port','other_ip'):
  s=socket.socket();s.settimeout(.5)
  s.connect((('127.0.0.1' if kind=='other_ip' else p['address']),p['other'] if kind=='other_port' else p['port']));s.close();ok=True
 elif kind=='dns':socket.socket(socket.AF_INET,socket.SOCK_DGRAM);ok=True
 elif kind=='ipv6':socket.socket(socket.AF_INET6,socket.SOCK_STREAM);ok=True
 elif kind=='firewall':ok=subprocess.run(['/usr/sbin/nft','flush','ruleset'],capture_output=True).returncode==0
 elif kind=='escape':
 libc=ctypes.CDLL(None,use_errno=True);result=libc.setns(-1,0x40000000)
 # EBADF without syscall filtering; EPERM proves the escape syscall is denied.
 ok=not (result==-1 and ctypes.get_errno()==1)
 elif kind=='readonly':
  with open(p['probe'],'w') as f:f.write('bad')
  ok=True
except OSError:pass
print(json.dumps({'allowed':ok,'caps':[l.strip() for l in open('/proc/self/status') if l.startswith(('CapEff:','CapPrm:','CapBnd:','NoNewPrivs:'))]}))
'''
            fds, child = boundary.launch_context(plan(address,port,'http'))
            result = subprocess.run([sys.executable,'-I','-c',code],pass_fds=fds,preexec_fn=child,
                capture_output=True,timeout=8,check=True,env={'UPTIP_TEST_PROBE':json.dumps(params)})
            value = json.loads(result.stdout)
            assert value['allowed'] is (scenario == 'allowed')
            assert all(int(line.split(':')[1].strip(),16)==0 for line in value['caps'] if line.startswith('Cap'))
            assert 'NoNewPrivs:\t1' in value['caps']
        assert not boundary.enforced and boundary._fds == ()
    finally:
        for listener in sockets: listener.close()
        temporary.cleanup()
