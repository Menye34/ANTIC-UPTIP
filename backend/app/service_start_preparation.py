"""Release-owned service scheduling, reviewed through normal Start confirmation.

Version 3 expands automatic HTTP/HTTPS discovery to eight common TCP ports.
Versions 1 and 2 remain immutable for historical receipts/consents; callers cannot select a
policy through request data. Scheduling never grants scanner dispatch.
"""
from copy import deepcopy
from .baseline_catalog import fingerprint
from .nmap_service_profile import CAPABILITY, authority, canonical_ports, plan

POLICY_ID = 'uptip-scoped-service-scheduling'
VERSION = 3
# Immutable release-owned definitions; never edit historical profiles in place.
V2_BASELINE_PORTS = (80, 443)
BASELINE_PORTS = (80, 443, 3000, 5000, 8000, 8080, 8443, 8888)


def policy(version=None):
    version = VERSION if version is None else version
    if type(version) is not int or version not in (1, 2, 3):
        raise ValueError('Unsupported service scheduling policy')
    if V2_BASELINE_PORTS != (80, 443) or BASELINE_PORTS != (80, 443, 3000, 5000, 8000, 8080, 8443, 8888):
        raise ValueError('Fixed baseline port definition changed')
    value = {'id': POLICY_ID, 'version': version, 'purpose': 'schedule_only',
             'dispatch_policy_digest': authority()['digest'],
             'scope': 'exact-ipv4-explicit-tcp-ports' if version == 1 else 'authorized-ipv4-fixed-web-ports',
             'max_ports': 16 if version == 1 else (2 if version == 2 else len(BASELINE_PORTS)),
             'required_capability': CAPABILITY, 'dependencies': ['network-discovery']}
    if version in (2, 3):
        value['baseline_tcp_ports'] = list(V2_BASELINE_PORTS if version == 2 else BASELINE_PORTS)
    return {**value, 'digest': fingerprint(value)}


def ports_for(db, assessment_id, target, version=None):
    from .scope_ports import authorized_ports
    version = VERSION if version is None else version
    policy(version)  # Reject unknown versions, never broaden a legacy boundary.
    legacy = authorized_ports(db, assessment_id, target)
    if version == 1:
        return legacy
    baseline = V2_BASELINE_PORTS if version == 2 else BASELINE_PORTS
    return [p for p in baseline if not legacy or p in legacy]


def prepare(host, ports=None, *, version=None):
    version = VERSION if version is None else version
    policy(version)
    baseline = V2_BASELINE_PORTS if version == 2 else BASELINE_PORTS
    ports = canonical_ports(list(baseline) if ports is None else ports)
    if version in (2, 3) and any(p not in baseline for p in ports):
        raise ValueError('Ports exceed the fixed service scheduling profile')
    value = {**deepcopy(host), 'profile_digest': authority()['digest'],
             'required_capability': CAPABILITY, 'scheduling_policy': policy(version),
             'host_preparation': deepcopy(host), 'authorized_tcp_ports': ports,
             'dependencies': ['network-discovery']}
    value['plan'] = plan(host['target_value'], ports)
    value['parameter_digest'] = value['plan']['parameter_digest']
    value.pop('fingerprint', None)
    value['fingerprint'] = fingerprint(value)
    return value


def validate(value):
    from .scheduling_policy import validate_preparation
    try:
        host = value['host_preparation']
        version = value['scheduling_policy']['version']
        return validate_preparation(host) and value == prepare(host, value['authorized_tcp_ports'], version=version)
    except (KeyError, TypeError, ValueError, RecursionError):
        return False
