"""Fail-closed tests for Nmap plan revalidation."""

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.nmap_assessment_binding import BoundNmapPlan
from app.nmap_execution_binding import (
    ExecutionBindingError,
    build_nmap_discovery_plan,
)
from app.nmap_discovery_profile import NMAP_DISCOVERY_PARAMETER_DIGEST
from app.nmap_plan_revalidation import revalidate_nmap_plan


class FakeSession:
    """Minimal session returning a Testing assessment."""

    def scalar(self, statement):
        return SimpleNamespace(status="Testing")


def make_bound_plan():
    return BoundNmapPlan(
        assessment_id=uuid4(),
        target_id=uuid4(),
        assessment_scope_revision=1,
        target_revision=1,
        evaluation_id=uuid4(),
        evaluation_fingerprint="a" * 64,
        policy_digest="b" * 64,
        plan=build_nmap_discovery_plan(
            target="192.0.2.10",
            approved_parameter_digest=NMAP_DISCOVERY_PARAMETER_DIGEST,
        ),
    )


def test_testing_rejects_missing_execution_request():
    bound_plan = make_bound_plan()

    with pytest.raises(
        ExecutionBindingError,
        match="persisted execution request",
    ):
        revalidate_nmap_plan(
            FakeSession(),
            bound_plan=bound_plan,
        )


def test_testing_rejects_unavailable_execution_request():
    bound_plan = make_bound_plan()

    class MissingRequestSession:
        def scalar(self, statement):
            if not hasattr(self, "calls"):
                self.calls = 0

            self.calls += 1

            if self.calls == 1:
                return SimpleNamespace(status="Testing")

            return None

    with pytest.raises(
        ExecutionBindingError,
        match="Execution request is unavailable",
    ):
        revalidate_nmap_plan(
            MissingRequestSession(),
            bound_plan=bound_plan,
            execution_request_id=uuid4(),
        )


def test_testing_rejects_missing_start_authorization():
    bound_plan = make_bound_plan()

    request = SimpleNamespace(
        authorization_id=uuid4(),
    )

    class MissingAuthorizationSession:
        def __init__(self):
            self.calls = 0

        def scalar(self, statement):
            self.calls += 1

            if self.calls == 1:
                return SimpleNamespace(status="Testing")

            if self.calls == 2:
                return request

            return None

    with pytest.raises(
        ExecutionBindingError,
        match="Confirmed Assessment Start authorization is unavailable",
    ):
        revalidate_nmap_plan(
            MissingAuthorizationSession(),
            bound_plan=bound_plan,
            execution_request_id=uuid4(),
        )
