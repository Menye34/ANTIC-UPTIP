"""Linux-only, non-root Nmap v2 adapter. Never accepts analyst argv or paths."""
import ctypes
from contextlib import nullcontext
from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

from .dispatch_policy import validate_plan as validate_host_plan
from .nmap_service_profile import validate_plan as validate_service_plan

def validate_plan(plan):
    return validate_host_plan(plan) or validate_service_plan(plan)



class AdapterUnavailable(ValueError):
    pass


@dataclass(frozen=True)
class AdapterConfig:
    executable: str
    sha256: str
    version: str
    timeout: int = 600
    output_limit: int = 10 * 1024 * 1024
    safety_interval: float = 5

    def __post_init__(self):
        if (not re.fullmatch(r'[0-9a-f]{64}', self.sha256)
                or not re.fullmatch(r'7\.[0-9]{2}', self.version)
                or not 1 <= self.timeout <= 600
                or not 1 <= self.output_limit <= 10 * 1024 * 1024
                or not 0 < self.safety_interval <= 5):
            raise AdapterUnavailable('invalid_executor_configuration')


@dataclass(frozen=True)
class ScanOutcome:
    stdout: bytes
    stderr: bytes
    exit_code: int | None
    reason: str
    terminated: bool
    partial: bool


def verify_privileges():
    if os.getuid() == 0 or os.geteuid() == 0 or os.getuid() != os.geteuid():
        raise AdapterUnavailable('unprivileged_worker_required')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if any(int(status[name].strip(), 16) for name in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb')):
        raise AdapterUnavailable('capability_free_worker_required')
    if os.environ.get('NMAP_PRIVILEGED') or os.environ.get('LD_PRELOAD') or os.environ.get('LD_LIBRARY_PATH'):
        raise AdapterUnavailable('unsafe_executor_environment')


def _no_new_privileges():
    if ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) != 0:
        raise OSError('Could not enforce no_new_privs')


def process_identity(pid):
    # Boot ID + PID + /proc start ticks; a reused PID is not the same process.
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return f'{boot}:{pid}:{fields[19]}'


class SupervisedToolAdapter:
    def __init__(self, config):
        self.config = config

    def _open_executable(self):
        verify_privileges()
        path = Path(self.config.executable)
        if not path.is_absolute() or str(path.resolve(strict=True)) != str(path):
            raise AdapterUnavailable('canonical_executable_path_required')
        for parent in path.parents:
            info = parent.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise AdapterUnavailable('untrusted_executable_directory')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
                    or not info.st_mode & 0o111):
                raise AdapterUnavailable('untrusted_executable_permissions')
            try:
                os.getxattr(fd, 'security.capability')
            except OSError as exc:
                if exc.errno != errno.ENODATA:
                    raise AdapterUnavailable('executable_capabilities_unverifiable') from exc
            else:
                raise AdapterUnavailable('privileged_executable_rejected')
            with os.fdopen(os.dup(fd), 'rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            if digest != self.config.sha256:
                raise AdapterUnavailable('executable_digest_mismatch')
            return fd
        except BaseException:
            os.close(fd)
            raise

    def validate_execution_plan(self, plan):
        return validate_plan(plan)

    def command(self, plan, version_probe):
        return ([self.config.executable, '--version'] if version_probe else
                [self.config.executable, *plan['arguments'], plan['target']])

    def environment(self):
        return {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                'HOME': '/nonexistent', 'NMAP_UNPRIVILEGED': '1'}

    def run(self, plan, *, safe, launched, version_probe=False, launch_guard=nullcontext):
        if not version_probe and not self.validate_execution_plan(plan):
            raise AdapterUnavailable('unsupported_invocation')
        try:
            fd = self._open_executable()
        except OSError as exc:
            raise AdapterUnavailable('trusted_executable_unavailable') from exc
        process = None
        buffers = [bytearray(), bytearray()]
        reason = 'scanner_exited'
        terminated = True
        try:
            argv = self.command(plan, version_probe)
            with launch_guard():
                if not safe():
                    raise AdapterUnavailable('prelaunch_authorization_denied')
                process = subprocess.Popen(argv, executable=f'/proc/self/fd/{fd}', pass_fds=(fd,),
                    shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env=self.environment(), cwd='/', start_new_session=True,
                    preexec_fn=_no_new_privileges)
                launched(process_identity(process.pid))
            deadline = time.monotonic() + (5 if version_probe else self.config.timeout)
            check_at = time.monotonic()
            with selectors.DefaultSelector() as selector:
                for index, stream in enumerate((process.stdout, process.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, index)
                while selector.get_map():
                    now = time.monotonic()
                    if now >= deadline:
                        reason = 'execution_timeout'
                        break
                    if now >= check_at:
                        if not safe():
                            reason = 'runtime_safety_lost'
                            break
                        check_at = now + self.config.safety_interval
                    for key, _ in selector.select(min(.1, max(0, deadline-now))):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        remaining = self.config.output_limit - sum(map(len, buffers))
                        buffers[key.data].extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            reason = 'output_limit_exceeded'
                            break
                    if reason != 'scanner_exited':
                        break
            if reason == 'scanner_exited':
                try:
                    process.wait(timeout=max(.01, deadline-time.monotonic()))
                except subprocess.TimeoutExpired:
                    reason = 'execution_timeout'
        except BaseException:
            if process is None:
                raise
            reason = 'adapter_or_launch_record_failure'
            terminated = self._stop(process)
        finally:
            os.close(fd)
            if process is not None:
                if process.poll() is None:
                    terminated = self._stop(process)
                for stream in (process.stdout, process.stderr):
                    stream.close()
                terminated = terminated and self._group_gone(process.pid)
        return ScanOutcome(bytes(buffers[0]), bytes(buffers[1]), process.returncode,
                           reason, terminated, not terminated or reason != 'scanner_exited' or process.returncode != 0)

    @staticmethod
    def _group_gone(pid):
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        return False

    @staticmethod
    def _stop(process):
        # Only signal the process group created by this live Popen handle.
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                return False
        except ProcessLookupError:
            try:
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                return False
        except OSError:
            return False
        return process.poll() is not None and SupervisedToolAdapter._group_gone(process.pid)

    def verify(self):
        outcome = self.run(None, safe=lambda: True, launched=lambda _: None, version_probe=True)
        if (outcome.exit_code != 0 or outcome.partial or not outcome.terminated
                or not outcome.stdout.startswith(f'Nmap version {self.config.version} '.encode())):
            raise AdapterUnavailable('unsupported_nmap_version')


class NmapAdapter(SupervisedToolAdapter):
    """Independent Nmap tool adapter using the shared process supervisor."""

