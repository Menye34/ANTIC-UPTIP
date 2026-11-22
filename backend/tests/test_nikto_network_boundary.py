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


@pytest.fixture
def simulated_setup(monkeypatch):
    """Exercise production initialization/cleanup with no real networking."""
    import tempfile
    import app.nikto_network_boundary as module
    calls, processes, pinned = [], [], []
    state = {'fail': None}
    original_open = os.open
    class Process:
        pid = 424242
        returncode = None
        def __init__(self, kind):
            self.kind = kind
            self.stdin, self.stdout, self.stderr = [tempfile.TemporaryFile() for _ in range(3)]
        def poll(self): return self.returncode
    def popen(args, **kwargs):
        kind = 'holder' if args[0] == TOOLS['unshare'] else 'slirp'
        calls.append((kind,args,kwargs))
        if state['fail'] == kind+'_start': raise PermissionError(13,'sensitive path must not appear')
        process=Process(kind);processes.append(process)
        return process
    def ready(fd, process):
        if state['fail'] == process.kind+'_ready':
            process.returncode=1
            if process.kind=='holder':
                process.stderr.write(b'uptip_holder_failure stage=mount_readonly errno=1\nprivate-secret\n')
                process.stderr.seek(0)
            raise AdapterUnavailable('nikto_namespace_ready_eof')
        return b'424242' if process.kind=='holder' else b'1'
    def opening(path, flags, *args, **kwargs):
        if str(path).startswith('/proc/424242/ns/'):
            if state['fail']=='namespace_pin': raise PermissionError(13,'private-secret')
            fd=original_open('/dev/null',flags);pinned.append(fd);return fd
        return original_open(path,flags,*args,**kwargs)
    def run(args,**kwargs):
        calls.append(('firewall',args,kwargs))
        if state['fail']=='firewall_install' or '--preserve-credentials' not in args:
            raise subprocess.CalledProcessError(1,args,stderr=b'nsenter: setgroups failed: Operation not permitted\nprivate-secret')
        return subprocess.CompletedProcess(args,0)
    def stop(process): process.returncode=-15;return True
    monkeypatch.setattr(module,'trusted_tool',lambda path:path)
    monkeypatch.setattr(module.subprocess,'Popen',popen)
    monkeypatch.setattr(module.subprocess,'run',run)
    monkeypatch.setattr(module,'read_ready',ready)
    monkeypatch.setattr(module.os,'open',opening)
    from app.nmap_adapter import SupervisedToolAdapter
    monkeypatch.setattr(SupervisedToolAdapter,'_stop',stop)
    return state,calls,processes,pinned


def test_setup_preserves_credentials_and_does_not_weaken_boundary(simulated_setup):
    _,calls,processes,pinned=simulated_setup
    boundary=NamespaceBoundary()
    with boundary.restrict('192.0.2.1',8080):
        assert boundary.enforced
        firewall=next(row for row in calls if row[0]=='firewall')
        assert '--preserve-credentials' in firewall[1]
        assert any(arg.startswith('--user=') for arg in firewall[1])
        assert any(arg.startswith('--net=') for arg in firewall[1])
        assert not any(arg.startswith('--setgroups') for arg in firewall[1])
        assert firewall[2]['input']==rules('192.0.2.1',8080).encode()
        slirp=next(row for row in calls if row[0]=='slirp')[1]
        for flag in ('--disable-host-loopback','--enable-sandbox','--enable-seccomp'):
            assert flag in slirp
        assert boundary._endpoint==('192.0.2.1',8080)
    assert not boundary.enforced and boundary._fds==()
    assert all(p.returncode==-15 for p in processes)
    for fd in pinned:
        with pytest.raises(OSError):os.fstat(fd)


@pytest.mark.parametrize('stage,reason,code,number',[
    ('holder_start','os_error',None,13),
    ('holder_ready','holder_mount_readonly_failed',1,1),
    ('namespace_pin','os_error',None,13),
    ('firewall_install','nsenter_setgroups_denied',1,None),
    ('slirp_start','os_error',None,13),
    ('slirp_ready','helper_ready_eof',1,None),
])
def test_setup_failures_identify_stage_without_exposing_raw_diagnostics(simulated_setup,caplog,stage,reason,code,number):
    from app.nikto_network_boundary import NamespaceSetupError
    state,_,processes,pinned=simulated_setup;state['fail']=stage
    boundary=NamespaceBoundary()
    with pytest.raises(NamespaceSetupError) as failure:
        with boundary.restrict('192.0.2.1',8080): pytest.fail('must not yield or launch scanner')
    error=failure.value
    assert (error.stage,error.reason,error.returncode,error.error_number)==(stage,reason,code,number)
    assert 'private-secret' not in caplog.text+str(error)
    assert 'sensitive path' not in caplog.text+str(error)
    assert stage in caplog.text and reason in caplog.text
    assert not boundary.enforced and boundary._fds==()
    assert all(p.poll() is not None for p in processes)
    for fd in pinned:
        with pytest.raises(OSError):os.fstat(fd)


def test_scanner_body_failures_are_not_mislabeled_setup_failures(simulated_setup,caplog):
    boundary=NamespaceBoundary()
    with pytest.raises(RuntimeError,match='caller failure'):
        with boundary.restrict('192.0.2.1',8080): raise RuntimeError('caller failure')
    assert 'nikto_containment_setup_failed' not in caplog.text
    assert not boundary.enforced


def test_setup_timeout_diagnostics_are_sanitized(caplog):
    from app.nikto_network_boundary import setup_failure
    error=setup_failure('firewall_install',subprocess.TimeoutExpired(['private-path'],5,stderr=b'private-secret'))
    assert error.reason=='helper_timeout' and error.returncode is None
    assert 'private-' not in caplog.text+str(error)


def test_rootless_nsenter_credential_preservation_smoke():
    """Real user/net/mount bootstrap only; no nft/slirp, scanner or network traffic.

    This is not one of the nine full kernel-containment acceptance scenarios.
    """
    from app.nikto_network_boundary import HOLDER,ENV,read_ready
    from app.nmap_adapter import _no_new_privileges
    if not all(Path(TOOLS[key]).exists() for key in ('unshare','nsenter','python')):
        pytest.skip('Rootless namespace smoke requires local util-linux/Python')
    probe=subprocess.run([TOOLS['unshare'],'--user','--map-root-user',TOOLS['python'],'-I','-c','pass'],
        capture_output=True,timeout=5,env=ENV)
    if probe.returncode:
        pytest.skip('Execution environment does not permit unprivileged user namespaces')
    process=subprocess.Popen([TOOLS['unshare'],'--user','--map-root-user','--net','--mount',
        TOOLS['python'],'-I','-c',HOLDER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env=ENV,start_new_session=True,preexec_fn=_no_new_privileges)
    try:
        assert int(read_ready(process.stdout.fileno(),process))==process.pid
        result=subprocess.run([TOOLS['nsenter'],'--preserve-credentials',f'--user=/proc/{process.pid}/ns/user',
            f'--net=/proc/{process.pid}/ns/net','--',TOOLS['python'],'-I','-c',
            "import os;print(os.geteuid());print(os.getgroups())"],capture_output=True,env=ENV,timeout=5)
        assert result.returncode==0,result.stderr.decode(errors='replace')
        assert result.stdout.splitlines()[0]==b'0'
    finally:
        process.stdin.close()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        process.stdout.close();process.stderr.close()
