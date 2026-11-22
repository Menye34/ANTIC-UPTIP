"""Explicit adapter registry for the shared execution worker.

Registry construction is side-effect free: no executable is opened and no
scanner is launched. Dispatch authorization remains the responsibility of the
existing verified scheduling/dispatch pipeline. A registered adapter alone
never makes a recommendation eligible or executable.
"""
from dataclasses import dataclass
from typing import Callable

from .nmap_adapter import AdapterConfig, NmapAdapter
from .nikto_adapter import NiktoAdapter, NiktoConfig


@dataclass(frozen=True)
class ToolAdapterSpec:
    tool: str
    profiles: frozenset[str]
    factory: Callable[[object], object]


SPECS = (
    ToolAdapterSpec('Nmap', frozenset({'host-discovery', 'service-discovery'}), NmapAdapter),
    ToolAdapterSpec('Nikto', frozenset({'nikto-http-service-restricted'}), NiktoAdapter),
)


def resolve_adapter(tool: str, profile_id: str, config: object):
    """Resolve a pinned tool/profile to an adapter; reject mismatched configs."""
    expected = {'Nmap': AdapterConfig, 'Nikto': NiktoConfig}
    if type(tool) is not str or type(profile_id) is not str:
        raise ValueError('unsupported_tool_profile')
    for spec in SPECS:
        if spec.tool == tool and profile_id in spec.profiles:
            if type(config) is not expected[tool]:
                raise ValueError('tool_configuration_mismatch')
            return spec.factory(config)
    raise ValueError('unsupported_tool_profile')
