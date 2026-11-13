"""Runtime safety decisions for restricted Nmap discovery.

This module evaluates safety conditions only.
It does not launch or terminate scanner processes.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeSafetyState:
    scope_unchanged: bool
    target_unchanged: bool
    authorization_valid: bool
    cancellation_requested: bool


@dataclass(frozen=True)
class RuntimeSafetyDecision:
    continue_execution: bool
    reason_code: str


def evaluate_runtime_safety(
    state: RuntimeSafetyState,
) -> RuntimeSafetyDecision:
    """Fail closed when any required runtime condition is violated."""

    if not state.authorization_valid:
        return RuntimeSafetyDecision(
            continue_execution=False,
            reason_code="authorization_invalid",
        )

    if not state.scope_unchanged:
        return RuntimeSafetyDecision(
            continue_execution=False,
            reason_code="scope_changed",
        )

    if not state.target_unchanged:
        return RuntimeSafetyDecision(
            continue_execution=False,
            reason_code="target_changed",
        )

    if state.cancellation_requested:
        return RuntimeSafetyDecision(
            continue_execution=False,
            reason_code="cancellation_requested",
        )

    return RuntimeSafetyDecision(
        continue_execution=True,
        reason_code="safety_conditions_satisfied",
    )
