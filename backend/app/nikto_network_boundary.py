"""Per-launch rootless user/net namespaces. No host firewall or worker setns.

The release profile stays disabled until Kali containment acceptance is complete.
This launcher requires trusted distro tools; missing capabilities fail closed.
"""
from contextlib import contextmanager
import ctypes
import ctypes.util
import errno
import logging
from ipaddress import IPv4Address, IPv4Network
import os
from pathlib import Path
import selectors
import stat
import subprocess

from .nmap_adapter import AdapterUnavailable, _no_new_privileges

TOOLS = {'unshare': '/usr/bin/unshare', 'nsenter': '/usr/bin/nsenter',
         'slirp': '/usr/bin/slirp4netns', 'nft': '/usr/sbin/nft', 'python': '/usr/bin/python3'}
LOG = logging.getLogger(__name__)
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/nonexistent'}
# The namespace holder performs no networking and is not the scanner. Its stdin
# lifetime is owned by the worker; dumpability is disabled before announcing PID.
HOLDER = '''import ctypes,os,sys,platform
libc=ctypes.CDLL(None,use_errno=True)
def checked(result,stage):
 if result:
  print('uptip_holder_failure stage='+stage+' errno='+str(ctypes.get_errno()),file=sys.stderr,flush=True)
  raise SystemExit(1)
if platform.machine() not in ('x86_64','aarch64'):
 print('uptip_holder_failure stage=architecture errno=0',file=sys.stderr,flush=True);raise SystemExit(1)
checked(libc.mount(None,b'/',None,16384|262144,None),'mount_private')
class Attr(ctypes.Structure):
 _fields_=[('set',ctypes.c_uint64),('clear',ctypes.c_uint64),('propagation',ctypes.c_uint64),('userns',ctypes.c_uint64)]
attr=Attr(1,0,0,0)
checked(libc.syscall(442,-100,b'/',32768,ctypes.byref(attr),ctypes.sizeof(attr)),'mount_readonly')
checked(libc.prctl(4,0,0,0,0),'dumpability')
print(os.getpid(),flush=True)
sys.stdin.buffer.read()
'''


class NamespaceSetupError(AdapterUnavailable):
    """Operator-only diagnostics made exclusively from fixed codes and integers."""
    def __init__(self, stage, reason, *, returncode=None, error_number=None):
        self.stage, self.reason = stage, reason
        self.returncode, self.error_number = returncode, error_number
        super().__init__(f'nikto_namespace_setup_failed stage={stage} reason={reason} '
                         f'exit={returncode} errno={error_number}')


def setup_failure(stage, exc, process=None):
    code = process.poll() if process is not None else None
    number = exc.errno if isinstance(exc, OSError) else None
    raw = b''
    reason = 'helper_failed'
    if isinstance(exc, subprocess.CalledProcessError):
        code = exc.returncode
        raw = (exc.stderr or b'')[:2048]
    elif isinstance(exc, subprocess.TimeoutExpired):
        reason = 'helper_timeout'
    elif isinstance(exc, OSError):
        reason = 'os_error'
    elif isinstance(exc, AdapterUnavailable):
        reason = {'nikto_namespace_identity_invalid':'holder_identity_invalid',
                  'nikto_namespace_ready_timeout':'helper_timeout',
                  'nikto_namespace_ready_eof':'helper_ready_eof',
                  'nikto_namespace_ready_invalid':'helper_ready_invalid'}.get(str(exc), 'helper_unavailable')
    # Only inspect bounded helper diagnostics; never return/log their text/argv.
    if process is not None and process.stderr is not None:
        try:
            os.set_blocking(process.stderr.fileno(), False)
            raw = os.read(process.stderr.fileno(), 2048)
        except (OSError, ValueError):
            pass
    if not isinstance(raw, bytes): raw = b''
    if b'setgroups failed' in raw:
        reason = 'nsenter_setgroups_denied'
    for holder_stage in ('architecture','mount_private','mount_readonly','dumpability'):
        token = ('uptip_holder_failure stage='+holder_stage+' errno=').encode()
        if token in raw:
            reason = 'holder_'+holder_stage+'_failed'
            digits = raw.split(token,1)[1].split(b'\n',1)[0]
            if digits.isdigit() and len(digits) <= 4: number = int(digits)
    error = NamespaceSetupError(stage, reason, returncode=code, error_number=number)
    LOG.warning('nikto_containment_setup_failed stage=%s reason=%s exit=%s errno=%s',
                stage, reason, code, number)
    return error


def trusted_tool(path):
    resolved = Path(path).resolve(strict=True)
    for directory in resolved.parents:
        info = directory.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise AdapterUnavailable('untrusted_isolation_tool')
    info = resolved.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
            or not info.st_mode & 0o111):
        raise AdapterUnavailable('untrusted_isolation_tool')
    try:
        os.getxattr(resolved, 'security.capability')
    except OSError as exc:
        if exc.errno != errno.ENODATA: raise AdapterUnavailable('unverifiable_isolation_tool') from None
    else:
        raise AdapterUnavailable('privileged_isolation_tool')
    return str(resolved)


def rules(target, port):
    """Only canonical literal interpolation; no analyst nft syntax is accepted."""
    if target is not None:
        ip = IPv4Address(target)
        if str(ip) != target or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip in IPv4Network('10.0.2.0/24'):
            raise AdapterUnavailable('nikto_namespace_target_unsupported')
        if type(port) is not int or not 1 <= port <= 65535 or port == 53:
            raise AdapterUnavailable('nikto_namespace_port_unsupported')
    allow = f'ip daddr {target} tcp dport {port} accept;' if target is not None else ''
    return f'''table inet uptip {{
chain input {{ type filter hook input priority 0; policy drop;
meta nfproto ipv6 drop; ct state established,related accept; }}
chain output {{ type filter hook output priority 0; policy drop;
meta nfproto ipv6 drop; {allow} }}
chain forward {{ type filter hook forward priority 0; policy drop; }}
}}
'''


def read_ready(fd, process):
    with selectors.DefaultSelector() as ready:
        ready.register(fd, selectors.EVENT_READ)
        if not ready.select(5):
            raise AdapterUnavailable('nikto_namespace_ready_timeout')
        if process.poll() is not None:
            raise AdapterUnavailable('nikto_namespace_ready_eof')
        value = os.read(fd, 64)
        if not value:
            process.poll()
            raise AdapterUnavailable('nikto_namespace_ready_eof')
        return value


class NamespaceBoundary:
    """One active context per single-process worker; nothing enters on construction."""
    def __init__(self):
        self._holder = self._slirp = None
        self._fds = ()
        self._endpoint = None
        self._installed = False
        self._poisoned = False

    @property
    def enforced(self):
        return bool(self._installed and self._holder is not None and self._holder.poll() is None
                    and (self._slirp is None or self._slirp.poll() is None))

    @contextmanager
    def restrict(self, target, port):
        if self._holder is not None or self._poisoned:
            raise AdapterUnavailable('nikto_namespace_already_active')
        script = rules(target, port)
        try:
            try:
                stage = 'helper_trust'
                tools = {key: trusted_tool(value) for key, value in TOOLS.items()}
                stage = 'holder_start'
                self._holder = subprocess.Popen([tools['unshare'], '--user', '--map-root-user', '--net', '--mount',
                    tools['python'], '-I', '-c', HOLDER], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, env=ENV, start_new_session=True, preexec_fn=_no_new_privileges)
                stage = 'holder_ready'
                pid_text = read_ready(self._holder.stdout.fileno(), self._holder).strip()
                if not pid_text.isdigit() or int(pid_text) != self._holder.pid:
                    raise AdapterUnavailable('nikto_namespace_identity_invalid')
                stage = 'namespace_pin'
                # Pin namespace identities rather than relying on a reusable PID at launch.
                self._fds = (os.open(f'/proc/{self._holder.pid}/ns/user', os.O_RDONLY | os.O_CLOEXEC),)
                self._fds += (os.open(f'/proc/{self._holder.pid}/ns/net', os.O_RDONLY | os.O_CLOEXEC),)
                self._fds += (os.open(f'/proc/{self._holder.pid}/ns/mnt', os.O_RDONLY | os.O_CLOEXEC),)
                # unshare --map-root-user writes setgroups=deny. nsenter must
                # not call setgroups; this trusted setup helper retains namespace
                # capabilities. The scanner still drops all capabilities later.
                enter = [tools['nsenter'], '--preserve-credentials', f'--user=/proc/{self._holder.pid}/ns/user',
                         f'--net=/proc/{self._holder.pid}/ns/net']
                stage = 'firewall_install'
                subprocess.run([*enter, '--', tools['nft'], '-f', '-'], input=script.encode(),
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=ENV, timeout=5, check=True)
                if target is not None:
                    stage = 'slirp_start'
                    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
                    try:
                        stage = 'slirp_start'
                        self._slirp = subprocess.Popen([tools['slirp'], '--configure', '--disable-host-loopback',
                            '--enable-sandbox', '--enable-seccomp', f'--ready-fd={write_fd}',
                            str(self._holder.pid), 'tap0'], pass_fds=(write_fd,), stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV,
                            start_new_session=True, preexec_fn=_no_new_privileges)
                        os.close(write_fd); write_fd = None
                        stage = 'slirp_ready'
                        if read_ready(read_fd, self._slirp) != b'1':
                            raise AdapterUnavailable('nikto_namespace_ready_invalid')
                    finally:
                        os.close(read_fd)
                        if write_fd is not None: os.close(write_fd)
                stage = 'boundary_verify'
                self._endpoint = (target, port)
                self._installed = True
                if not self.enforced: raise AdapterUnavailable('nikto_namespace_ready_invalid')
            except (OSError, subprocess.SubprocessError, ValueError) as exc:
                process = self._slirp if stage.startswith('slirp') else self._holder if stage in ('holder_start','holder_ready','namespace_pin') else None
                raise setup_failure(stage, exc, process) from None
            yield self
        finally:
            self._installed = False
            for process in (self._slirp, self._holder):
                if process is not None:
                    from .nmap_adapter import SupervisedToolAdapter
                    if process.poll() is None and not SupervisedToolAdapter._stop(process):
                        # No subsequent scan may reuse a context with uncertain helpers.
                        self._poisoned = True
                    for stream in (process.stdin, process.stdout, process.stderr):
                        if stream is not None: stream.close()
            for fd in self._fds: os.close(fd)
            self._fds = ()
            self._holder = self._slirp = None
            self._endpoint = None
            if self._poisoned:
                raise setup_failure('cleanup', AdapterUnavailable('nikto_namespace_cleanup_unverified')) from None

    def launch_context(self, plan):
        endpoint = (plan['target'], plan['port']) if plan else (None, None)
        if not self.enforced or endpoint != self._endpoint:
            raise AdapterUnavailable('nikto_network_boundary_required')
        user_fd, net_fd, mount_fd = self._fds
        try:
            seccomp = ctypes.CDLL(ctypes.util.find_library('seccomp') or 'libseccomp.so.2', use_errno=True)
        except OSError:
            raise AdapterUnavailable('nikto_seccomp_unavailable') from None
        seccomp.seccomp_init.restype = ctypes.c_void_p
        seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
        seccomp.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
        seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
        seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
        seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
        class Compare(ctypes.Structure):
            _fields_ = [('arg', ctypes.c_uint), ('op', ctypes.c_int), ('a', ctypes.c_uint64), ('b', ctypes.c_uint64)]
        def enter_child():
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.setns(user_fd, 0x10000000) or libc.setns(net_fd, 0x40000000) or libc.setns(mount_fd, 0x20000):
                raise OSError('namespace_entry_failed')
            os.close(user_fd); os.close(net_fd); os.close(mount_fd)
            # No capability can survive exec or reappear through UID 0 semantics.
            if libc.prctl(28, 3, 0, 0, 0): raise OSError('securebits_failed')
            for cap in range(64):
                if libc.prctl(24, cap, 0, 0, 0) and ctypes.get_errno() != errno.EINVAL:
                    raise OSError('capability_drop_failed')
            class Header(ctypes.Structure): _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
            class Data(ctypes.Structure): _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32), ('inheritable', ctypes.c_uint32)]
            header, data = Header(0x20080522, 0), (Data * 2)()
            if libc.capset(ctypes.byref(header), ctypes.byref(data)):
                raise OSError('capability_drop_failed')
            _no_new_privileges()
            context = seccomp.seccomp_init(0x7fff0000)  # Allow except explicit escape/IPC operations.
            if not context: raise OSError('seccomp_setup_failed')
            try:
                deny = 0x00050000 | errno.EPERM
                def rule(name, *comparisons):
                    number = seccomp.seccomp_syscall_resolve_name(name.encode())
                    if number < 0 or seccomp.seccomp_rule_add(context, deny, number, len(comparisons), *comparisons):
                        raise OSError('seccomp_setup_failed')
                # Filesystem UNIX sockets bypass net namespaces unless denied.
                rule('socket', Compare(0, 1, 2, 0))  # domain != AF_INET
                rule('socket', Compare(1, 7, 15, 2))  # SOCK_DGRAM, including socket flags
                rule('socket', Compare(1, 7, 15, 3))  # SOCK_RAW
                for name in ('socketpair','setns','unshare','ptrace','process_vm_readv','process_vm_writev',
                             'pidfd_getfd','mount','umount2','mount_setattr','fsopen','fsmount','move_mount','open_tree','bpf',
                             'io_uring_setup','io_uring_enter','io_uring_register'):
                    rule(name)
                if seccomp.seccomp_load(context): raise OSError('seccomp_setup_failed')
            finally:
                seccomp.seccomp_release(context)
        return self._fds, enter_child
