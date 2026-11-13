"""Read-only revalidation of bound Nmap discovery plans.

Candidate plans are validated during Draft.
Testing requires a separate trusted dispatch authorization chain.

This module never launches or authorizes a scanner.
"""

from sqlalchemy import select
from hmac import compare_digest
from .baseline_catalog import fingerprint
from .assessment_start import SNAPSHOT_VERSION

from .models import (
    Assessment,
    AssessmentStartAuthorization,
    BaselineExecutionRequest,
)
from .nmap_assessment_binding import (
    BoundNmapPlan,
    bind_nmap_plan,
)
from .nmap_execution_binding import ExecutionBindingError


def revalidate_nmap_plan(
    db,
    *,
    bound_plan: BoundNmapPlan,
    execution_request_id=None,
) -> BoundNmapPlan:
    """Revalidate a plan without granting execution authority."""

    if not isinstance(bound_plan, BoundNmapPlan):
        raise ExecutionBindingError("Invalid bound execution plan.")

    assessment = db.scalar(
        select(Assessment).where(
            Assessment.id == bound_plan.assessment_id
        )
    )

    if assessment is None:
        raise ExecutionBindingError("Assessment is unavailable.")

    if assessment.status == "Draft":
        current = bind_nmap_plan(
            db,
            assessment_id=bound_plan.assessment_id,
            target_id=bound_plan.target_id,
        )

        if current != bound_plan:
            raise ExecutionBindingError(
                "Assessment execution plan is stale or has changed."
            )

        return current

    if assessment.status == "Testing":
        if execution_request_id is None:
            raise ExecutionBindingError(
                "Testing requires a persisted execution request."
            )

        request = db.scalar(
            select(BaselineExecutionRequest).where(
                BaselineExecutionRequest.id == execution_request_id,
                BaselineExecutionRequest.assessment_id
                    == bound_plan.assessment_id,
                BaselineExecutionRequest.target_id
                    == bound_plan.target_id,
            )
        )

        if request is None:
            raise ExecutionBindingError(
                "Execution request is unavailable."
            )

        authorization = db.scalar(
            select(AssessmentStartAuthorization).where(
                AssessmentStartAuthorization.id
                    == request.authorization_id,
                AssessmentStartAuthorization.assessment_id
                    == bound_plan.assessment_id,
            )
        )

        if authorization is None:
            raise ExecutionBindingError(
                "Confirmed Assessment Start authorization is unavailable."
            )

        if (
            request.tool != "Nmap"
            or request.activity != "Network Discovery"
            or request.profile_id != bound_plan.plan.profile_id
            or request.profile_version != bound_plan.plan.profile_version
            or request.status not in ("Queued", "Running")
        ):
            raise ExecutionBindingError(
                "Execution request does not match the Nmap discovery plan."
            )

        if (
            not isinstance(authorization.snapshot, dict)
            or not isinstance(request.authorized_activity, dict)
            or authorization.snapshot.get("scope_revision")
                != bound_plan.assessment_scope_revision
        ):
            raise ExecutionBindingError(
                "Persisted execution authorization binding is invalid."
            )

        snapshot = authorization.snapshot

        if (
            authorization.snapshot_version != SNAPSHOT_VERSION
            or snapshot.get("schema_version") != SNAPSHOT_VERSION
            or snapshot.get("assessment_id")
                != str(bound_plan.assessment_id)
            or snapshot.get("lifecycle_status") != "Draft"
            or snapshot.get("mode") not in ("full", "partial")
            or authorization.mode != snapshot.get("mode")
        ):
            raise ExecutionBindingError(
                "Assessment Start snapshot identity is invalid."
            )

        expected_digest = fingerprint(snapshot)

        if (
            not isinstance(authorization.snapshot_digest, str)
            or not compare_digest(
                expected_digest,
                authorization.snapshot_digest,
            )
        ):
            raise ExecutionBindingError(
                "Assessment Start snapshot integrity verification failed."
            )

        matching_targets = [
            item
            for item in snapshot.get("targets", [])
            if isinstance(item, dict)
            and item.get("target_id") == str(bound_plan.target_id)
            and item.get("revision") == bound_plan.target_revision
            and item.get("value") == bound_plan.plan.target
            and item.get("scope_status") == "in_scope"
        ]

        if len(matching_targets) != 1:
            raise ExecutionBindingError(
                "Authorized target does not match the bound Nmap plan."
            )

        matching_activities = [
            item
            for item in snapshot.get("eligible_activities", [])
            if isinstance(item, dict)
            and item.get("target_id") == str(bound_plan.target_id)
            and item.get("profile_id") == request.profile_id
            and item.get("version") == request.profile_version
            and item.get("tool") == request.tool
            and item.get("activity") == request.activity
        ]

        if len(matching_activities) != 1:
            raise ExecutionBindingError(
                "Exactly one authorized Nmap activity is required."
            )

        activity = matching_activities[0]

        expected_request_activity = {
            **activity,
            "target_value": matching_targets[0]["value"],
        }

        if request.authorized_activity != expected_request_activity:
            raise ExecutionBindingError(
                "Execution request differs from the authorized activity."
            )

        if (
            activity.get("status") != "resolved"
            or activity.get("policy", {}).get("disposition")
                != "preauthorized"
            or str(activity.get("evaluation_id"))
                != str(bound_plan.evaluation_id)
            or activity.get("evaluation_fingerprint")
                != bound_plan.evaluation_fingerprint
            or snapshot.get("policy", {}).get("digest")
                != bound_plan.policy_digest
        ):
            raise ExecutionBindingError(
                "Authorized activity does not match the bound baseline."
            )

        raise ExecutionBindingError(
            "Snapshot and activity binding verified; trusted policy, "
            "current safety evidence, and runtime authorization "
            "verification remain required."
        )

    raise ExecutionBindingError(
        "Assessment lifecycle does not permit plan revalidation."
    )
