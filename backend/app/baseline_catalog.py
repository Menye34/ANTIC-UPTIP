"""System-managed baseline definitions. Each changed definition needs a new version."""
from dataclasses import asdict, dataclass
from hashlib import sha256
import json


def fingerprint(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


@dataclass(frozen=True)
class Profile:
    key: str
    version: int
    tool: str
    activity: str
    description: str
    capability: str
    kinds: tuple[str, ...]
    restriction: str

    def snapshot(self):
        definition = asdict(self)
        return {**definition, 'digest': fingerprint(definition)}


PROFILES = (
    Profile('network-discovery', 1, 'Nmap', 'Network Discovery',
            'Prepare network discovery for an explicitly authorized IPv4 target.',
            'ipv4-discovery', ('IP address', 'Subnet'), 'Only the authorized IPv4 address or contained subnet.'),
    Profile('web-discovery', 1, 'OWASP ZAP', 'Web Discovery',
            'Prepare passive and crawl discovery for an explicitly authorized web URL.',
            'passive-web-discovery', ('Web URL',), 'Only the exact authorized HTTP(S) URL. No host or network inference.'),
)

TOOL_STATES = ('enabled', 'disabled', 'unavailable', 'unknown')
