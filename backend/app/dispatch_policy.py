"""Release-owned dispatch authority; distinct from immutable scheduling consent.

Only Network Discovery v2 under a non-root, capability-free Linux executor.
No analyst-controlled parameters or operational approval records are accepted.
"""
from copy import deepcopy
from ipaddress import IPv4Address

from .baseline_catalog import Profile, fingerprint

PROFILE = Profile('network-discovery', 2, 'Nmap', 'Network Discovery',
    'Unprivileged IPv4 host discovery with bounded XML output and no DNS.',
    'ipv4-discovery', ('IP address',), 'Exactly one currently authorized canonical IPv4 address.')
PARAMETERS = {
    'profile_id': 'network-discovery', 'profile_version': 2, 'tool': 'Nmap',
    'activity': 'Network Discovery', 'capability': 'ipv4-discovery',
    'target_kind': 'IP address', 'arguments': ['-sn', '-n', '-oX', '-'],
    'risk': 'low', 'max_units': 1, 'allow_port_scanning': False,
    'allow_scripts': False, 'allow_target_expansion': False,
}
POLICY = {
    'id': 'uptip-ipv4-discovery-dispatch', 'version': 1, 'purpose': 'dispatch',
    'approval_source': 'reviewed-application-release', 'profile': PROFILE.snapshot(),
    'parameters': PARAMETERS, 'probe_policy': 'unprivileged-tcp-connect-80-443',
    'max_processes': 1, 'max_seconds': 600, 'max_output_bytes': 10 * 1024 * 1024,
    'runtime_interval_seconds': 5,
    'requirements': ['active-creator', 'current-scope', 'current-baseline',
                     'immutable-start-binding', 'trusted-executable', 'exclusive-live-claim'],
}
_RELEASE_DIGEST = fingerprint(POLICY)


def authority():
    if fingerprint(POLICY) != _RELEASE_DIGEST:
        raise ValueError('dispatch_release_integrity_invalid')
    return {**deepcopy(POLICY), 'digest': fingerprint(POLICY)}


def plan(target):
    authority()
    if not isinstance(target, str) or str(IPv4Address(target)) != target:
        raise ValueError('canonical_ipv4_required')
    return {'target': target, 'arguments': list(PARAMETERS['arguments']),
            'profile_id': PROFILE.key, 'profile_version': PROFILE.version,
            'parameter_digest': fingerprint(PARAMETERS)}


def validate_plan(candidate):
    try:
        return candidate == plan(candidate['target'])
    except (ValueError, TypeError, KeyError):
        return False
