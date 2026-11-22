"""Release-owned versioned Nikto profiles with system-enforced activation."""
from copy import deepcopy
from ipaddress import IPv4Address
import re

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
# Never mutate the historical disabled v1 definition or its digest.
POLICY_V2 = {**deepcopy(POLICY), 'version': 2, 'profile_version': 2,
    'execution_enabled': True,
    'scanner_version': '2.6.1',
    'fixed_arguments': ['-nointeractive', '-nocheck', '-nolookup', '-timeout', '10',
                        '-maxtime', '300s', '-Tuning', '123b', '-Plugins', 'headers;tests']}
_DIGEST_V2 = fingerprint(POLICY_V2)


def authority(version=VERSION):
    if type(version) is not int or version not in (1, 2):
        raise ValueError('nikto_policy_version_unsupported')
    policy, digest = (POLICY, _DIGEST) if version == 1 else (POLICY_V2, _DIGEST_V2)
    if fingerprint(policy) != digest:
        raise ValueError('nikto_profile_integrity_invalid')
    return {**deepcopy(policy), 'digest': digest}


def activation():
    # Trusted system configuration selects one exact release policy.
    # Analyst consent is verified separately for each recommended execution.
    from .config import get_settings
    settings = get_settings()
    version = settings.nikto_policy_version
    digest = settings.nikto_policy_digest
    if version is None and digest is None:
        return {'policy': authority(1)}
    if type(version) is not int or version != 2:
        raise ValueError('nikto_policy_activation_invalid')
    policy = authority(version)
    from hmac import compare_digest
    if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest) or not compare_digest(digest, policy['digest']):
        raise ValueError('nikto_policy_activation_invalid')
    return {'policy': policy}


def integration_available():
    try:
        selected = activation()['policy']
        return selected['version'] == 2 and selected['execution_enabled'] is True
    except (ValueError, TypeError):
        return False


def dispatch_enabled(candidate):
    try:
        selected = activation()['policy']
        return (selected['execution_enabled'] is True and selected['version'] == 2
                and validate_plan(candidate) and candidate['profile_version'] == selected['version']
                and candidate['policy_digest'] == selected['digest'])
    except (ValueError, TypeError, KeyError):
        return False


def plan(target, port, scheme, *, version=VERSION):
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
    policy = authority(version)
    identity = {'target': target, 'port': port, 'scheme': scheme,
                'profile_id': PROFILE_ID, 'profile_version': policy['version'],
                'policy_digest': policy['digest']}
    return {**identity, 'parameter_digest': fingerprint(identity),
            'endpoint_preview': f'{scheme}://{target}:{port}/'}


def validate_plan(candidate):
    if not isinstance(candidate, dict):
        return False
    try:
        return candidate == plan(candidate['target'], candidate['port'], candidate['scheme'], version=candidate['profile_version'])
    except (ValueError, TypeError, KeyError):
        return False
