"""Read-only verification for system-managed Nmap discovery readiness.

This module does not authorize or execute scanners.
"""

from dataclasses import dataclass

from .nmap_discovery_profile import (
    NMAP_DISCOVERY_PARAMETER_DIGEST,
    NMAP_DISCOVERY_PROFILE,
)


@dataclass(frozen=True)
class SafetyVerification:
    passed: bool
    checks: tuple[str, ...]
    pending: tuple[str, ...]


def verify_nmap_discovery(
    *,
    in_scope: bool,
    baseline_current: bool,
    tool_capable: bool,
    target_kind: str,
    profile_id: str,
    profile_version: int,
) -> SafetyVerification:
    """Verify independently established assessment facts."""

    checks = []
    pending = []

    conditions = {
        "authorized_scope": in_scope,
        "current_baseline": baseline_current,
        "tool_capability": tool_capable,
        "target_kind": target_kind == "IP address",
        "profile_identity": (
            profile_id == NMAP_DISCOVERY_PROFILE["profile_id"]
            and profile_version == NMAP_DISCOVERY_PROFILE["profile_version"]
        ),
        "restricted_profile_configured": (
            NMAP_DISCOVERY_PROFILE["arguments"] == ["-sn"]
            and NMAP_DISCOVERY_PROFILE["allow_port_scanning"] is False
            and NMAP_DISCOVERY_PROFILE["allow_scripts"] is False
            and NMAP_DISCOVERY_PROFILE["allow_target_expansion"] is False
            and len(NMAP_DISCOVERY_PARAMETER_DIGEST) == 64
        ),
    }

    for name, satisfied in conditions.items():
        (checks if satisfied else pending).append(name)

    # A configured profile does not prove that a future scanner
    # invocation will use those parameters or honor stop conditions.
    pending.extend((
        "executor_parameter_binding",
        "runtime_stop_condition_enforcement",
    ))

    return SafetyVerification(
        passed=not pending,
        checks=tuple(checks),
        pending=tuple(pending),
    )
