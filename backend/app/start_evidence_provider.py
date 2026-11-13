"""Read-only provider for governed assessment-start safety evidence."""

import json
from datetime import datetime, timezone

from pydantic import ValidationError
from sqlalchemy import select

from .assessment_readiness import PrerequisiteCompletion, StartEvidence
from .models import (
    AssessmentStartEvidenceRecord,
    AuthorizationRecordRevocation,
    ExecutionPolicyApprovalRecord,
)
from .start_evidence_schema import StartEvidenceDocument


def load_trusted_start_evidence(
    db,
    assessment_id,
    target_id,
    evaluation_id,
    evaluation_fingerprint,
    policy_digest,
    approval_reference,
):
    """Return uniquely valid, non-revoked evidence or fail closed."""

    if not approval_reference:
        return None

    now = datetime.now(timezone.utc)

    from .system_authorization_verifier import verify_system_authorization

    # Retrieve evidence by its exact assessment and evaluation identity.
    # The authorization source is determined by the persisted evidence row.
    records = db.scalars(
        select(AssessmentStartEvidenceRecord)
        .outerjoin(
            AuthorizationRecordRevocation,
            AuthorizationRecordRevocation.evidence_reference
            == AssessmentStartEvidenceRecord.reference,
        )
        .where(
            AssessmentStartEvidenceRecord.assessment_id == assessment_id,
            AssessmentStartEvidenceRecord.target_id == target_id,
            AssessmentStartEvidenceRecord.evaluation_id == evaluation_id,
            AssessmentStartEvidenceRecord.evaluation_fingerprint
            == evaluation_fingerprint,
            AssessmentStartEvidenceRecord.policy_digest == policy_digest,
            AssessmentStartEvidenceRecord.valid_from <= now,
            AssessmentStartEvidenceRecord.valid_until > now,
            AuthorizationRecordRevocation.id.is_(None),
            (
                (AssessmentStartEvidenceRecord.approval_reference == approval_reference)
                & AssessmentStartEvidenceRecord.system_authorization_reference.is_(None)
            )
            |
            (
                (AssessmentStartEvidenceRecord.system_authorization_reference
                 == approval_reference)
                & AssessmentStartEvidenceRecord.approval_reference.is_(None)
            ),
        )
    ).all()

    if len(records) != 1:
        return None

    record = records[0]

    if record.system_authorization_reference is not None:
        verification = verify_system_authorization(
            db,
            record.system_authorization_reference,
            policy_digest,
            now=now,
        )
        if not verification["valid"]:
            return None

    elif record.approval_reference is not None:
        approval = db.scalar(
            select(ExecutionPolicyApprovalRecord).where(
                ExecutionPolicyApprovalRecord.reference
                == record.approval_reference,
                ExecutionPolicyApprovalRecord.policy_digest == policy_digest,
                ExecutionPolicyApprovalRecord.valid_from <= now,
                ExecutionPolicyApprovalRecord.valid_until > now,
            )
        )

        if approval is None:
            return None

        revoked = db.scalar(
            select(AuthorizationRecordRevocation.id).where(
                AuthorizationRecordRevocation.approval_reference
                == record.approval_reference
            )
        )

        if revoked is not None:
            return None

    else:
        return None

    try:
        document = StartEvidenceDocument.model_validate_json(
            json.dumps(record.evidence)
        )
    except (ValidationError, TypeError, ValueError):
        return None

    completions = tuple(
        PrerequisiteCompletion(
            target_id=item.target_id,
            profile_id=item.profile_id,
            evaluation_id=item.evaluation_id,
            evaluation_fingerprint=item.evaluation_fingerprint,
            policy_digest=item.policy_digest,
            reference=item.reference,
            successful=item.successful,
            completed_at=item.completed_at,
            expires_at=item.expires_at,
        )
        for item in document.prerequisite_completions
    )

    return StartEvidence(
        reference=record.reference,
        expires_at=record.valid_until,
        parameter_digest=document.parameter_digest,
        risk=document.risk,
        verified_prerequisites=document.verified_prerequisites,
        requested_units=document.requested_units,
        clear_stop_conditions=document.clear_stop_conditions,
        mandatory_activities=document.mandatory_activities,
        prerequisite_completions=completions,
    )
