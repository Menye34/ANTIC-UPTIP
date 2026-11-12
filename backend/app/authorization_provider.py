"""Read-only trusted authorization providers.

These providers do not grant execution authority.
"""

from datetime import datetime, timezone

from sqlalchemy import select

from .execution_policy import PolicySelection, select_policy
from .models import (
    AuthorizationRecordRevocation,
    ExecutionPolicyApprovalRecord,
    ExecutionPolicyVersion,
)


def load_trusted_policy(db):
    """Select one currently valid, non-revoked governed policy.

    Ambiguous or unavailable authorization fails closed.
    """
    now = datetime.now(timezone.utc)

    candidates = db.execute(
        select(ExecutionPolicyVersion, ExecutionPolicyApprovalRecord)
        .join(
            ExecutionPolicyApprovalRecord,
            ExecutionPolicyApprovalRecord.policy_digest
            == ExecutionPolicyVersion.digest,
        )
        .outerjoin(
            AuthorizationRecordRevocation,
            AuthorizationRecordRevocation.approval_reference
            == ExecutionPolicyApprovalRecord.reference,
        )
        .where(
            ExecutionPolicyApprovalRecord.valid_from <= now,
            ExecutionPolicyApprovalRecord.valid_until > now,
            AuthorizationRecordRevocation.id.is_(None),
        )
    ).all()

    # Phase C2.4: inspect persisted system-managed authorizations.
    # This is read-only and does not grant execution permission.
    from .system_authorization_models import SystemPolicyAuthorizationRecord
    from .system_authorization_verifier import verify_system_authorization

    system_records = db.execute(
        select(SystemPolicyAuthorizationRecord)
    ).scalars().all()

    verified_system_records = [
        record for record in system_records
        if verify_system_authorization(
            db,
            record.reference,
            record.policy_digest,
            now=now,
        )["valid"]
    ]

    if len(verified_system_records) > 1:
        return PolicySelection(
            'invalid',
            'system_authorization_ambiguous',
            'Multiple valid system-managed authorizations prevent trusted selection.',
        )

    # Fail closed if system-managed authorization records exist
    # but none passes verification.
    if system_records and not verified_system_records:
        return PolicySelection(
            'invalid',
            'system_authorization_unverified',
            'System-managed authorization records exist, '
            'but none is currently valid.',
        )

    if verified_system_records:
        if candidates:
            return PolicySelection(
                'invalid',
                'authorization_sources_ambiguous',
                'Both legacy and system-managed authorizations are active.',
            )

        record = verified_system_records[0]

        version = db.execute(
            select(ExecutionPolicyVersion).where(
                ExecutionPolicyVersion.digest == record.policy_digest
            )
        ).scalar_one_or_none()

        if version is None:
            return PolicySelection(
                'invalid',
                'system_policy_version_missing',
                'Authorized system policy version was not found.',
            )

        from .execution_policy import PolicyDefinition
        from pydantic import ValidationError

        try:
            definition = PolicyDefinition.model_validate(
                version.definition
            )
        except (ValidationError, TypeError, ValueError):
            return PolicySelection(
                'invalid',
                'system_policy_definition_invalid',
                'Authorized system policy definition is invalid.',
            )

        approval = {
            'policy_id': version.policy_id,
            'version': version.version,
            'digest': record.policy_digest,
            'provenance': record.provenance,
            'reference': record.reference,
            'expires_at': record.valid_until,
        }

        return select_policy(definition, approval)

    if not candidates:
        from .system_policy_catalog import configured_policy

        definition = configured_policy()
        if definition is not None:
            return PolicySelection(
                'configured',
                'system_policy_configured',
                'Versioned system-managed execution policy is configured; '
                'activity safety verification is still required.',
                definition=definition,
            )
        return select_policy(None, None)

    if len(candidates) != 1:
        return PolicySelection(
            'invalid',
            'execution_policy_ambiguous',
            'Multiple active policy approvals prevent trusted selection.',
        )

    version, record = candidates[0]

    approval = {
        'policy_id': version.policy_id,
        'version': version.version,
        'digest': record.policy_digest,
        'provenance': record.provenance,
        'reference': record.reference,
        'expires_at': record.valid_until,
    }

    from pydantic import ValidationError
    from .execution_policy import PolicyDefinition
    import json

    try:
        definition = PolicyDefinition.model_validate_json(
            json.dumps(version.definition)
        )
    except (ValidationError, TypeError, ValueError):
        return PolicySelection(
            'invalid',
            'execution_policy_invalid',
            'Persisted execution policy definition is invalid.',
        )

    return select_policy(definition, approval)
