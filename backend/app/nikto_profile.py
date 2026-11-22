"""Release-owned Nikto HTTP service profile (pre-dispatch validation only).

This module does not grant authorization or enable worker dispatch. A future
adapter must enforce the exact endpoint boundary at the network layer before
this profile can be marked executable.
"""
from copy import deepcopy
from ipaddress import IPv4Address

from .baseline_catalog import fingerprint

PROFILE_ID = 'nikto-http-service-restricted'
VERSION = 1
POLICY = {
    'id': 'uptip-nikto-http-service-restricted',
    'version': VERSION,
    'profile_id': PROFILE_ID,
    'profile_version': VERSION,
    'tool': 'Nikto',
    'activity': 'HTTP Server Assessment',
    'capability': 'http-server-assessment',
    'protocols': ['http', 'https'],
    'max_processes': 1,
    'max_seconds': 300,
    'max_output_bytes': 5 * 1024 * 1024,
    'network_boundary': 'exact_ipv4_tcp_endpoint',
    'redirects': 'deny',
    'dns': 'deny',
    'proxies': 'deny',
    'execution_enabled': False,
}
_DIGEST = fingerprint(POLICY)


def authority():
    if fingerprint(POLICY) != _DIGEST:
        raise ValueError('nikto_profile_integrity_invalid')
    return {**deepcopy(POLICY), 'digest': _DIGEST}


def plan(target, port, scheme):
    """Canonical, unambiguous endpoint identity; never an argv or URL grant."""
    if not isinstance(target, str):
        raise ValueError('canonical_ipv4_required')
    try:
        ip = IPv4Address(target)
    except (ValueError, TypeError) as exc:
        raise ValueError('canonical_ipv4_required') from exc
    if str(ip) != target or ip.is_multicast or ip.is_unspecified:
        raise ValueError('canonical_ipv4_required')
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('valid_tcp_port_required')
    if scheme not in ('http', 'https') or not isinstance(scheme, str):
        raise ValueError('explicit_http_scheme_required')
    policy = authority()
    identity = {'target': target, 'port': port, 'scheme': scheme,
                'profile_id': PROFILE_ID, 'profile_version': VERSION,
                'policy_digest': policy['digest']}
    return {**identity, 'parameter_digest': fingerprint(identity),
            'endpoint_preview': f'{scheme}://{target}:{port}/'}


def validate_plan(candidate):
    if not isinstance(candidate, dict):
        return False
    try:
        return candidate == plan(candidate['target'], candidate['port'], candidate['scheme'])
    except (ValueError, TypeError, KeyError):
        return False
