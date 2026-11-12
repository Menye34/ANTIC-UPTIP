"""Restricted Nmap discovery configuration.

This module defines permitted parameters only.
It does not launch Nmap or authorize scanner execution.
"""

from .baseline_catalog import fingerprint

NMAP_DISCOVERY_PROFILE = {
    "profile_id": "network-discovery",
    "profile_version": 1,
    "tool": "Nmap",
    "activity": "Network Discovery",
    "capability": "ipv4-discovery",
    "target_kind": "IP address",
    "arguments": ["-sn"],
    "risk": "low",
    "max_units": 1,
    "allow_port_scanning": False,
    "allow_scripts": False,
    "allow_target_expansion": False,
}

NMAP_DISCOVERY_PARAMETER_DIGEST = fingerprint(
    NMAP_DISCOVERY_PROFILE
)
