"""Continuous supervision of an existing restricted discovery process.

Does not launch scanners or grant execution authorization.
"""

from dataclasses import dataclass
from threading import Event
from typing import Callable

from .nmap_process_supervisor import supervise_process
from .nmap_runtime_safety import RuntimeSafetyState


@dataclass(frozen=True)
class MonitoringResult:
    completed: bool
    stopped_for_safety: bool
    reason_code: str


def monitor_process(
    *,
    process,
    safety_state_provider: Callable[[], RuntimeSafetyState],
    interval: float = 0.5,
    termination_timeout: float = 3.0,
) -> MonitoringResult:
    """Monitor an existing process until exit or safety failure."""

    if interval <= 0:
        raise ValueError("Monitoring interval must be positive.")

    wake_event = Event()

    while True:
        result = supervise_process(
            process=process,
            safety_state_provider=safety_state_provider,
            termination_timeout=termination_timeout,
        )

        if result.reason_code != "safety_conditions_satisfied":
            return MonitoringResult(
                completed=False,
                stopped_for_safety=result.stopped,
                reason_code=result.reason_code,
            )

        if process.poll() is not None:
            return MonitoringResult(
                completed=True,
                stopped_for_safety=False,
                reason_code="process_exited",
            )

        wake_event.wait(interval)
