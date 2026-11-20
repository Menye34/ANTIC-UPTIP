"""Versioned service scheduling facts, derived from explicit IPv4 scope ports.

This is scheduling consent, not a dispatch decision. Runtime consent, ownership,
policy, scope and executable verification remain mandatory.
"""
from copy import deepcopy
from .baseline_catalog import fingerprint
from .nmap_service_profile import CAPABILITY, authority, plan

POLICY_ID = 'uptip-scoped-service-scheduling'
VERSION = 1


def policy():
    value = {'id': POLICY_ID, 'version': VERSION, 'purpose': 'schedule_only',
             'dispatch_policy_digest': authority()['digest'],
             'scope': 'exact-ipv4-explicit-tcp-ports', 'max_ports': 16,
             'required_capability': CAPABILITY, 'dependencies': ['network-discovery']}
    return {**value, 'digest': fingerprint(value)}


def prepare(host, ports):
    value = {**deepcopy(host), 'profile_digest': authority()['digest'],
             'required_capability': CAPABILITY, 'scheduling_policy': policy(),
             'host_preparation': deepcopy(host), 'authorized_tcp_ports': list(ports),
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
        return validate_preparation(host) and value == prepare(host, value['authorized_tcp_ports'])
    except (KeyError, TypeError, ValueError, RecursionError):
        return False
