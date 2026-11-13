"""Security tests for restricted Nmap execution-plan binding."""

import pytest

from app.nmap_discovery_profile import NMAP_DISCOVERY_PARAMETER_DIGEST
from app.nmap_execution_binding import (
    ExecutionBindingError,
    build_nmap_discovery_plan,
)


def build(target, digest=NMAP_DISCOVERY_PARAMETER_DIGEST):
    return build_nmap_discovery_plan(
        target=target,
        approved_parameter_digest=digest,
    )


def test_valid_ipv4_produces_restricted_plan():
    plan = build("192.168.10.1")

    assert plan.target == "192.168.10.1"
    assert plan.arguments == ("-sn",)
    assert plan.profile_id == "network-discovery"
    assert plan.profile_version == 1
    assert plan.parameter_digest == NMAP_DISCOVERY_PARAMETER_DIGEST


@pytest.mark.parametrize("target", [
    "192.168.10.0/24",
    "example.com",
    "192.168.10.1 192.168.10.2",
    "2001:db8::1",
    "192.168.10.1 --script vuln",
    "192.168.10.1\n192.168.10.2",
    "",
    None,
])
def test_unsupported_targets_are_rejected(target):
    with pytest.raises(ExecutionBindingError):
        build(target)


def test_unapproved_parameter_digest_is_rejected():
    with pytest.raises(ExecutionBindingError):
        build("192.168.10.1", "invalid-digest")


def test_missing_parameter_digest_is_rejected():
    with pytest.raises(ExecutionBindingError):
        build("192.168.10.1", None)
