"""Restricted Nikto adapter reusing Nmap's supervised, bounded subprocess runner.

No execution authorization is granted by this adapter. The caller must provide
fresh authorization, exact endpoint containment, and an operator-pinned binary.
"""
from dataclasses import dataclass
import re

from .nmap_adapter import SupervisedToolAdapter, AdapterUnavailable
from .nikto_profile import validate_plan


@dataclass(frozen=True)
class NiktoConfig:
    executable: str
    sha256: str
    version: str
    timeout: int = 300
    output_limit: int = 5 * 1024 * 1024
    safety_interval: float = 5

    def __post_init__(self):
        if (not isinstance(self.executable, str) or not self.executable.startswith('/')
                or not re.fullmatch(r'[a-f0-9]{64}', self.sha256)
                or self.version != '2.6.1'
                or type(self.timeout) is not int or not 1 <= self.timeout <= 300
                or type(self.output_limit) is not int or not 1 <= self.output_limit <= 5 * 1024 * 1024
                or not isinstance(self.safety_interval, (int, float))
                or not 0 < self.safety_interval <= 5):
            raise AdapterUnavailable('invalid_nikto_executor_configuration')


class NiktoAdapter(SupervisedToolAdapter):
    """Reuse process identity, privileges, pinning, supervision and termination."""

    def __init__(self, config, *, boundary=None):
        super().__init__(config)
        self.boundary = boundary

    def launch_context(self, plan, version_probe):
        if self.boundary is None:
            raise AdapterUnavailable('nikto_network_boundary_required')
        return self.boundary.launch_context(None if version_probe else plan)

    def validate_execution_plan(self, plan):
        return validate_plan(plan)

    def command(self, plan, version_probe):
        if version_probe:
            return [self.config.executable, '-Version']
        if not validate_plan(plan):
            raise AdapterUnavailable('invalid_nikto_plan')
        # Fixed argv: no free-form URL, shell, proxy, plugin or user-supplied flags.
        # Redirects and DNS lookups are disabled; runtime network isolation must
        # independently enforce the exact authorized IPv4:port endpoint.
        argv = [self.config.executable, '-host', plan['target'], '-port', str(plan['port']),
                '-nointeractive', '-nocheck', '-nolookup',
                '-timeout', '10', '-maxtime', '300s', '-Tuning', '123b', '-Plugins', 'headers;tests']
        if plan['scheme'] == 'https':
            argv.append('-ssl')
        return argv

    def environment(self):
        # Explicitly omit proxy variables and the Nmap-specific flag.
        return {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                'HOME': '/nonexistent', 'PERL5OPT': ''}

    def verify(self):
        outcome = self.run(None, safe=lambda: True, launched=lambda _: None,
                           version_probe=True)
        if (outcome.exit_code != 0 or outcome.partial or not outcome.terminated
                or not re.search(rb'Nikto\s+(?:v|version\s*)' + re.escape(self.config.version.encode()) + rb'\b',
                                 outcome.stdout + b'\n' + outcome.stderr, re.I)):
            raise AdapterUnavailable('unsupported_nikto_version')
