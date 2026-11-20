"""Release-owned opt-in TCP service discovery. Never an automatic baseline."""
from copy import deepcopy
from ipaddress import IPv4Address
from .baseline_catalog import fingerprint

PROFILE_ID = 'service-discovery'
VERSION = 1
CAPABILITY = 'tcp-service-discovery'
POLICY = {
    'id': 'uptip-tcp-service-discovery', 'version': 1, 'purpose': 'dispatch',
    'profile_id': PROFILE_ID, 'profile_version': VERSION,
    'tool': 'Nmap', 'activity': 'Service Discovery', 'capability': CAPABILITY,
    'max_ports': 16, 'max_processes': 1, 'max_seconds': 600,
    'max_output_bytes': 10 * 1024 * 1024, 'runtime_interval_seconds': 5,
    'risk': 'restricted-active-service-detection',
    'nse': 'standard-built-in-version-detection-only',
    'arguments': ['-sT', '-sV', '--version-light', '-Pn', '-n',
                  '--max-retries', '1', '--max-parallelism', '4',
                  '--max-rate', '20', '--host-timeout', '300s', '-oX', '-'],
}
_DIGEST = fingerprint(POLICY)


def authority():
    if fingerprint(POLICY) != _DIGEST:
        raise ValueError('service_policy_integrity_invalid')
    return {**deepcopy(POLICY), 'digest': _DIGEST}


def canonical_ports(ports):
    if (not isinstance(ports, (list, tuple)) or not 1 <= len(ports) <= 16
            or any(type(p) is not int or not 1 <= p <= 65535 for p in ports)
            or len(set(ports)) != len(ports)):
        raise ValueError('explicit_unique_tcp_ports_required')
    return sorted(ports)


def plan(target, ports):
    policy = authority()
    if not isinstance(target, str) or str(IPv4Address(target)) != target:
        raise ValueError('canonical_ipv4_required')
    ports = canonical_ports(ports)
    envelope = {'policy_digest': policy['digest'], 'target': target, 'ports': ports}
    return {'target': target, 'ports': ports, 'profile_id': PROFILE_ID,
            'profile_version': VERSION, 'parameter_digest': fingerprint(envelope),
            'arguments': [*policy['arguments'], '-p', ','.join(map(str, ports))]}


def validate_plan(candidate):
    try:
        return candidate == plan(candidate['target'], candidate['ports'])
    except (ValueError, TypeError, KeyError):
        return False
