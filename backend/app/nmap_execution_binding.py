"""Restricted Nmap discovery execution-plan binding.

This module constructs a candidate execution plan.
It does not authorize execution or launch Nmap.
"""

from dataclasses import dataclass
from ipaddress import IPv4Address, ip_address

from .baseline_catalog import fingerprint
from .nmap_discovery_profile import (
    NMAP_DISCOVERY_PARAMETER_DIGEST,
    NMAP_DISCOVERY_PROFILE,
)


@dataclass(frozen=True)
class NmapExecutionPlan:
    target: str
    arguments: tuple[str, ...]
    profile_id: str
    profile_version: int
    parameter_digest: str


class ExecutionBindingError(ValueError):
    """Raised when a discovery plan cannot be safely constructed."""


def build_nmap_discovery_plan(
    *,
    target: str,
    approved_parameter_digest: str,
) -> NmapExecutionPlan:
    """Build a restricted, non-executable Nmap discovery plan."""

    if not isinstance(target, str):
        raise ExecutionBindingError("Target must be an IPv4 address.")

    try:
        address = ip_address(target)
    except ValueError as exc:
        raise ExecutionBindingError(
            "Target must be one IPv4 address."
        ) from exc

    if not isinstance(address, IPv4Address):
        raise ExecutionBindingError("IPv6 is not supported by this profile.")

    if target != str(address):
        raise ExecutionBindingError(
            "Target must use canonical IPv4 notation."
        )

    profile = NMAP_DISCOVERY_PROFILE

    if fingerprint(profile) != NMAP_DISCOVERY_PARAMETER_DIGEST:
        raise ExecutionBindingError(
            "Configured Nmap profile integrity check failed."
        )

    if (
        not isinstance(approved_parameter_digest, str)
        or approved_parameter_digest != NMAP_DISCOVERY_PARAMETER_DIGEST
    ):
        raise ExecutionBindingError(
            "Nmap profile does not match the approved policy."
        )

    if (
        profile["arguments"] != ["-sn"]
        or profile["allow_port_scanning"] is not False
        or profile["allow_scripts"] is not False
        or profile["allow_target_expansion"] is not False
        or profile["max_units"] != 1
    ):
        raise ExecutionBindingError(
            "Configured Nmap profile is not restricted."
        )

    return NmapExecutionPlan(
        target=str(address),
        arguments=tuple(profile["arguments"]),
        profile_id=profile["profile_id"],
        profile_version=profile["profile_version"],
        parameter_digest=NMAP_DISCOVERY_PARAMETER_DIGEST,
    )
