"""Database-backed runtime safety state for Nmap discovery.

Fail-closed foundation. Does not authorize or execute scanners.
"""

from sqlalchemy import select

from .models import (
    Assessment,
    AssessmentTarget,
    BaselineExecutionRequest,
)
from .nmap_assessment_binding import BoundNmapPlan
from .nmap_plan_revalidation import revalidate_nmap_plan
from .nmap_runtime_safety import RuntimeSafetyState


def load_nmap_runtime_state(
    db,
    *,
    bound_plan: BoundNmapPlan,
    execution_request_id,
) -> RuntimeSafetyState:
    """Evaluate persisted runtime conditions without granting authorization."""

    assessment = db.scalar(
        select(Assessment).where(
            Assessment.id == bound_plan.assessment_id
        )
    )

    target = db.scalar(
        select(AssessmentTarget).where(
            AssessmentTarget.id == bound_plan.target_id,
            AssessmentTarget.assessment_id == bound_plan.assessment_id,
        )
    )

    request = db.scalar(
        select(BaselineExecutionRequest).where(
            BaselineExecutionRequest.id == execution_request_id,
            BaselineExecutionRequest.assessment_id == bound_plan.assessment_id,
            BaselineExecutionRequest.target_id == bound_plan.target_id,
        )
    )

    scope_unchanged = (
        assessment is not None
        and target is not None
        and assessment.scope_revision
            == bound_plan.assessment_scope_revision
        and target.scope_revision
            == bound_plan.assessment_scope_revision
    )

    target_unchanged = (
        target is not None
        and target.revision == bound_plan.target_revision
        and target.normalized_value == bound_plan.plan.target
    )

    request_matches = (
        request is not None
        and request.profile_id == bound_plan.plan.profile_id
        and request.profile_version == bound_plan.plan.profile_version
        and request.tool == "Nmap"
        and request.activity == "Network Discovery"
    )

    cancellation_requested = (
        request is not None
        and request.status in ("Cancelled", "Stopped", "Blocked")
    )

    binding_current = False

    if scope_unchanged and target_unchanged:
        try:
            revalidate_nmap_plan(db, bound_plan=bound_plan)
            binding_current = True
        except Exception:
            binding_current = False

    # Deliberately fail closed until trusted system-managed
    # dispatch authorization is implemented and verified.
    authorization_valid = False

    return RuntimeSafetyState(
        scope_unchanged=bool(scope_unchanged),
        target_unchanged=bool(target_unchanged and binding_current),
        authorization_valid=authorization_valid,
        cancellation_requested=bool(
            cancellation_requested
            or not request_matches
            or request is None
            or request.status != "Running"
        ),
    )
