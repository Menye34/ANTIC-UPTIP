"""Read-only binding of restricted Nmap plans to assessment state.

A bound plan is not authorization to execute a scanner.
"""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select

from .assessment_readiness import evaluate_readiness
from .models import Assessment, AssessmentTarget
from .nmap_discovery_profile import NMAP_DISCOVERY_PARAMETER_DIGEST
from .scheduling_policy import public_policy
from .nmap_execution_binding import (
    ExecutionBindingError,
    NmapExecutionPlan,
    build_nmap_discovery_plan,
)


@dataclass(frozen=True)
class BoundNmapPlan:
    assessment_id: UUID
    target_id: UUID
    assessment_scope_revision: int
    target_revision: int
    evaluation_id: UUID
    evaluation_fingerprint: str
    policy_digest: str
    plan: NmapExecutionPlan


def bind_nmap_plan(db, *, assessment_id: UUID, target_id: UUID) -> BoundNmapPlan:
    """Build a candidate plan bound to current persisted assessment state."""

    assessment = db.scalar(
        select(Assessment).where(Assessment.id == assessment_id)
    )

    if assessment is None or assessment.status != "Draft":
        raise ExecutionBindingError("Assessment is unavailable or not Draft.")

    target = db.scalar(
        select(AssessmentTarget).where(
            AssessmentTarget.id == target_id,
            AssessmentTarget.assessment_id == assessment_id,
        )
    )

    if target is None:
        raise ExecutionBindingError("Target does not belong to this assessment.")

    readiness = evaluate_readiness(db, assessment)

    policy = readiness.get("policy") or {}

    if policy.get("status") != "system_managed" or policy.get("purpose") != "schedule_only":
        raise ExecutionBindingError(
            "Expected system-managed execution policy is unavailable."
        )

    trusted_policy = public_policy()

    if (
        policy.get("id") != trusted_policy['id']
        or policy.get("version") != trusted_policy['version']
        or policy.get("digest") != trusted_policy['digest']
    ):
        raise ExecutionBindingError(
            "System execution policy integrity verification failed."
        )

    target_state = next(
        (
            item for item in readiness.get("targets", [])
            if str(item.get("target_id")) == str(target_id)
        ),
        None,
    )

    if target_state is None or target_state.get("scope_status") != "in_scope":
        raise ExecutionBindingError("Target is not in authorized scope.")

    if target.scope_revision != assessment.scope_revision:
        raise ExecutionBindingError("Target scope revision is stale.")

    activity = next(
        (
            item
            for item in target_state.get("baseline_activities", [])
            if item.get("activity") == "Network Discovery"
            and item.get("tool") == "Nmap"
            and item.get("profile_id") == "network-discovery"
            and item.get("version") == 1
        ),
        None,
    )

    if (activity is None or activity.get("status") != "resolved"
            or not activity.get('start_review_eligible')):
        raise ExecutionBindingError("Current Nmap baseline is unavailable.")

    evaluation_id = activity.get("evaluation_id")
    evaluation_fingerprint = activity.get("evaluation_fingerprint")

    if not evaluation_id or not evaluation_fingerprint:
        raise ExecutionBindingError("Baseline evidence is incomplete.")

    plan = build_nmap_discovery_plan(
        target=target.normalized_value,
        approved_parameter_digest=NMAP_DISCOVERY_PARAMETER_DIGEST,
    )

    return BoundNmapPlan(
        assessment_id=assessment.id,
        target_id=target.id,
        assessment_scope_revision=assessment.scope_revision,
        target_revision=target.revision,
        evaluation_id=UUID(str(evaluation_id)),
        evaluation_fingerprint=evaluation_fingerprint,
        policy_digest=policy["digest"],
        plan=plan,
    )
