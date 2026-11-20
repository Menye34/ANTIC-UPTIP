"""Release-owned planning objectives, not executable scanner registrations."""
from dataclasses import dataclass
from .baseline_catalog import fingerprint

@dataclass(frozen=True)
class Capability:
    key: str
    version: int
    test: str
    tool: str
    description: str
    source_type: str
    integrated: bool = False
    profile_id: str | None = None

    def snapshot(self):
        value = vars(self)
        return {**value, 'digest': fingerprint(value)}

# These are planning definitions only. They do not register tools, executable
# profiles, adapters or dispatch permissions. Nmap's implemented host-discovery
# profile cannot perform either objective and is never substituted here.
CAPABILITIES = (
    Capability('http-server-assessment', 1, 'HTTP Server Assessment', 'Nikto',
        'Assess an explicitly observed HTTP server for server configuration and exposed-resource issues.', 'service_discovery'),
    Capability('web-application-assessment', 1, 'Web Application Assessment', 'OWASP ZAP',
        'Assess an explicitly evidenced web application within its separately authorized URL boundary.', 'web_application'),
)
