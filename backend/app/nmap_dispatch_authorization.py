"""Fail-closed Nmap dispatch authorization foundation.

Read-only verification. Does not launch scanners, claim execution
requests, or grant permission while required safety checks are pending.
"""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select

from .authorization_provider import load_trusted_policy
from .models import (
    Assessment,
    AssessmentStartAuthorization,
    BaselineExecutionRequest,
)


@dataclass(frozen=True)
class DispatchAuthorizationDecision:
    authorized: bool
    reason_code: str


def verify_nmap_dispatch_authorization(
    db,
    *,
    execution_request_id: UUID,
) -> DispatchAuthorizationDecision:
    """Verify dispatch prerequisites, denying by default."""

    def deny(reason: str) -> DispatchAuthorizationDecision:
        return DispatchAuthorizationDecision(False, reason)

    try:
        request = db.scalar(
            select(BaselineExecutionRequest).where(
                BaselineExecutionRequest.id == execution_request_id
            )
        )

        if request is None:
            return deny("execution_request_not_found")

        if request.status != "Queued":
            return deny("execution_request_not_queued")

        if request.tool != "Nmap" or request.activity != "Network Discovery":
            return deny("unsupported_execution_activity")

        assessment = db.scalar(
            select(Assessment).where(
                Assessment.id == request.assessment_id
            )
        )

        if assessment is None or assessment.status != "Testing":
            return deny("assessment_not_in_testing")

        authorization = db.scalar(
            select(AssessmentStartAuthorization).where(
                AssessmentStartAuthorization.id == request.authorization_id,
                AssessmentStartAuthorization.assessment_id
                == request.assessment_id,
            )
        )

        if authorization is None:
            return deny("start_authorization_not_found")

        # Scheduling consent is not an execution approval, regardless of any
        # independently configured execution policy. Keep dispatch disabled.
        if isinstance(authorization.snapshot, dict) and authorization.snapshot.get('purpose') == 'schedule_only':
            return deny('dispatch_safety_checks_pending')

        policy = load_trusted_policy(db)

        if (
            policy.status != "approved"
            or policy.definition is None
            or policy.approval is None
        ):
            return deny("trusted_policy_not_approved")

        snapshot = authorization.snapshot

        if not isinstance(snapshot, dict):
            return deny("invalid_start_authorization_snapshot")

        integrity = verify_start_snapshot_integrity(
            authorization, request, snapshot
        )
        if integrity.reason_code != "start_snapshot_integrity_verified":
            return integrity

        snapshot_policy = snapshot.get("policy")

        if not isinstance(snapshot_policy, dict):
            return deny("missing_snapshot_policy")

        if snapshot_policy.get("digest") != policy.definition.digest:
            return deny("start_policy_digest_mismatch")

        system_auth = verify_dispatch_system_authorization(
            db, snapshot_policy, policy
        )
        if (
            system_auth.reason_code
            != "system_authorization_verified_dispatch_pending"
        ):
            return system_auth

        # Outstanding prerequisites:
        # - Exact execution-to-snapshot activity binding
        # - Current scope and target revalidation
        # - Approved parameter digest verification
        # - Fresh system authorization verification
        # - Runtime stop-condition enforcement
        #
        # These must be implemented and tested before dispatch is allowed.
        binding = verify_execution_snapshot_binding(request, snapshot)
        if binding.reason_code != "execution_snapshot_binding_verified_dispatch_pending":
            return binding

        scope_binding = verify_current_scope_target(
            db, assessment, request, snapshot
        )
        if (
            scope_binding.reason_code
            != "current_scope_target_binding_verified_dispatch_pending"
        ):
            return scope_binding

        return deny("dispatch_safety_checks_pending")

    except Exception:
        return deny("dispatch_verification_unavailable")


def verify_execution_snapshot_binding(request, snapshot):
    """Verify that a queued request matches its authorized Start activity.

    This check does not grant execution permission.
    """
    def deny(reason):
        return DispatchAuthorizationDecision(False, reason)

    if not isinstance(snapshot, dict):
        return deny("invalid_start_authorization_snapshot")

    if str(request.assessment_id) != str(snapshot.get("assessment_id")):
        return deny("execution_assessment_mismatch")

    activities = snapshot.get("eligible_activities")
    if not isinstance(activities, list):
        return deny("missing_eligible_activities")

    matches = [
        activity
        for activity in activities
        if isinstance(activity, dict)
        and activity.get("target_id") == str(request.target_id)
        and activity.get("profile_id") == request.profile_id
    ]

    if len(matches) != 1:
        return deny("execution_activity_binding_mismatch")

    activity = matches[0]

    if (
        activity.get("version") != request.profile_version
        or activity.get("tool") != request.tool
        or activity.get("activity") != request.activity
    ):
        return deny("execution_activity_details_mismatch")

    if (
        activity.get("status") != "resolved"
        or not isinstance(activity.get("policy"), dict)
        or activity["policy"].get("disposition") != "preauthorized"
    ):
        return deny("execution_activity_not_preauthorized")

    if not isinstance(request.authorized_activity, dict):
        return deny("invalid_queued_activity_evidence")

    targets = snapshot.get("targets")
    if not isinstance(targets, list):
        return deny("missing_snapshot_targets")

    matching_targets = [
        target
        for target in targets
        if isinstance(target, dict)
        and target.get("target_id") == str(request.target_id)
    ]

    if len(matching_targets) != 1:
        return deny("execution_target_binding_mismatch")

    expected_activity = {
        **activity,
        "target_value": matching_targets[0].get("value"),
    }

    if request.authorized_activity != expected_activity:
        return deny("queued_activity_evidence_mismatch")

    # Binding verification succeeded, but dispatch remains prohibited.
    return DispatchAuthorizationDecision(
        False,
        "execution_snapshot_binding_verified_dispatch_pending",
    )


def verify_current_scope_target(db, assessment, request, snapshot):
    """Verify current scope and target against the Start snapshot.

    This function never grants scanner execution permission.
    """
    from .models import AssessmentTarget

    def deny(reason):
        return DispatchAuthorizationDecision(False, reason)

    if not isinstance(snapshot, dict):
        return deny("invalid_start_authorization_snapshot")

    if (
        not isinstance(snapshot.get("scope_revision"), int)
        or isinstance(snapshot["scope_revision"], bool)
        or assessment.scope_revision != snapshot["scope_revision"]
    ):
        return deny("assessment_scope_revision_changed")

    from .target_scope import scope_entries
    from .baseline_catalog import fingerprint
    from hmac import compare_digest

    expected_digest = snapshot.get("scope_digest")

    if not isinstance(expected_digest, str) or not expected_digest:
        return deny("missing_snapshot_scope_digest")

    current_boundaries = scope_entries(db, assessment.id)
    current_digest = fingerprint(sorted(map(list, current_boundaries)))

    if not compare_digest(current_digest, expected_digest):
        return deny("assessment_scope_digest_changed")

    targets = snapshot.get("targets")

    if not isinstance(targets, list):
        return deny("missing_snapshot_targets")

    matches = [
        item for item in targets
        if isinstance(item, dict)
        and item.get("target_id") == str(request.target_id)
    ]

    if len(matches) != 1:
        return deny("snapshot_target_binding_mismatch")

    expected = matches[0]

    target = db.scalar(
        select(AssessmentTarget).where(
            AssessmentTarget.id == request.target_id,
            AssessmentTarget.assessment_id == request.assessment_id,
        )
    )

    if target is None:
        return deny("current_target_not_found")

    if (
        target.scope_status != "in_scope"
        or expected.get("scope_status") != "in_scope"
    ):
        return deny("target_not_in_scope")

    if (
        target.scope_revision != assessment.scope_revision
        or target.revision != expected.get("revision")
    ):
        return deny("target_revision_changed")

    if (
        target.normalized_value != expected.get("value")
        or target.kind != expected.get("kind")
    ):
        return deny("target_identity_changed")

    return DispatchAuthorizationDecision(
        False,
        "current_scope_target_binding_verified_dispatch_pending",
    )


def verify_start_snapshot_integrity(authorization, request, snapshot):
    """Verify persisted Start snapshot identity and integrity.

    Successful verification never grants scanner dispatch permission.
    """
    from hmac import compare_digest
    from .assessment_start import SNAPSHOT_VERSION, LEGACY_SNAPSHOT_VERSION
    from .baseline_catalog import fingerprint

    def deny(reason):
        return DispatchAuthorizationDecision(False, reason)

    if not isinstance(snapshot, dict):
        return deny("invalid_start_authorization_snapshot")

    if (
        type(authorization.snapshot_version) is not int
        or authorization.snapshot_version not in (SNAPSHOT_VERSION, LEGACY_SNAPSHOT_VERSION)
        or type(snapshot.get("schema_version")) is not int
        or snapshot["schema_version"] != authorization.snapshot_version
    ):
        return deny("start_snapshot_version_mismatch")

    if (
        str(authorization.assessment_id) != str(request.assessment_id)
        or snapshot.get("assessment_id") != str(request.assessment_id)
    ):
        return deny("start_snapshot_assessment_mismatch")

    if snapshot.get("lifecycle_status") != "Draft":
        return deny("start_snapshot_lifecycle_mismatch")

    if (
        authorization.mode not in ("full", "partial")
        or snapshot.get("mode") != authorization.mode
    ):
        return deny("start_snapshot_mode_mismatch")

    stored_digest = authorization.snapshot_digest

    if (
        not isinstance(stored_digest, str)
        or len(stored_digest) != 64
    ):
        return deny("invalid_start_snapshot_digest")

    try:
        current_digest = fingerprint(snapshot)
    except (TypeError, ValueError):
        return deny("invalid_start_snapshot_content")

    if not compare_digest(current_digest, stored_digest):
        return deny("start_snapshot_integrity_mismatch")

    return DispatchAuthorizationDecision(
        False,
        "start_snapshot_integrity_verified",
    )



def verify_dispatch_system_authorization(db, snapshot_policy, policy):
    """Verify the Start-bound system authorization at dispatch time.

    Verification is read-only and never grants scanner permission.
    """
    from .system_authorization_verifier import (
        verify_system_authorization,
    )

    def deny(reason):
        return DispatchAuthorizationDecision(False, reason)

    if not isinstance(snapshot_policy, dict):
        return deny("invalid_snapshot_policy")

    reference = snapshot_policy.get("approval_reference")
    digest = snapshot_policy.get("digest")

    if (
        not isinstance(reference, str)
        or not reference.strip()
        or not isinstance(digest, str)
        or not digest.strip()
    ):
        return deny("missing_start_system_authorization")

    approval = policy.approval

    if not isinstance(approval, dict):
        return deny("invalid_current_policy_approval")

    if approval.get("reference") != reference:
        return deny("start_system_authorization_reference_mismatch")

    if approval.get("digest") != digest:
        return deny("start_system_authorization_policy_mismatch")

    result = verify_system_authorization(
        db,
        reference,
        digest,
    )

    if not isinstance(result, dict) or result.get("valid") is not True:
        return deny("start_system_authorization_invalid")

    return DispatchAuthorizationDecision(
        False,
        "system_authorization_verified_dispatch_pending",
    )
