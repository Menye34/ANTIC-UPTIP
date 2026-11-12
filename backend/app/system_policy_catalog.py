"""Versioned system-managed execution policy definitions.

Policies define permitted activity envelopes. They do not establish
completed safety checks or authorize scanner dispatch.
"""

from .execution_policy import PolicyDefinition, PolicyRule
from .nmap_discovery_profile import NMAP_DISCOVERY_PARAMETER_DIGEST


def configured_policy() -> PolicyDefinition:
    """Return the built-in Nmap discovery policy definition."""
    return PolicyDefinition(
        policy_id="uptip-system-discovery",
        version=1,
        rules=(
            PolicyRule(
                rule_id="nmap-ipv4-discovery-v1",
                activity="Network Discovery",
                tool="Nmap",
                capability="ipv4-discovery",
                target_kind="IP address",
                profile_id="network-discovery",
                profile_version=1,
                disposition="preauthorized",
                parameter_digest=NMAP_DISCOVERY_PARAMETER_DIGEST,
                risk="low",
                prerequisites=("authorized_scope", "tool_capability"),
                max_units=1,
                stop_conditions=("scope_unchanged", "no_target_expansion"),
            ),
        ),
    )
