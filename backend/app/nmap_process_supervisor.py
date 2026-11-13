"""Fail-closed supervision of an existing process.

This module does not launch scanners or authorize execution.
"""

from dataclasses import dataclass
from subprocess import TimeoutExpired
from typing import Callable

from .nmap_runtime_safety import (
    RuntimeSafetyState,
    evaluate_runtime_safety,
)


@dataclass(frozen=True)
class SupervisionResult:
    stopped: bool
    reason_code: str


def supervise_process(
    *,
    process,
    safety_state_provider: Callable[[], RuntimeSafetyState],
    termination_timeout: float = 3.0,
) -> SupervisionResult:
    """Evaluate safety and request process termination when unsafe."""

    if termination_timeout <= 0:
        raise ValueError("Termination timeout must be positive.")

    try:
        decision = evaluate_runtime_safety(safety_state_provider())
    except Exception:
        decision = None

    if decision is not None and decision.continue_execution:
        return SupervisionResult(
            stopped=False,
            reason_code=decision.reason_code,
        )

    reason = (
        decision.reason_code
        if decision is not None
        else "safety_verification_unavailable"
    )

    try:
        if process.poll() is not None:
            return SupervisionResult(True, reason)

        process.terminate()

        try:
            process.wait(timeout=termination_timeout)
        except TimeoutExpired:
            process.kill()
            process.wait(timeout=termination_timeout)

        if process.poll() is None:
            return SupervisionResult(
                False,
                "process_exit_unconfirmed",
            )

        return SupervisionResult(True, reason)

    except Exception:
        return SupervisionResult(
            False,
            "process_termination_unconfirmed",
        )
