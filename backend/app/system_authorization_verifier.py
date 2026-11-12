"""Fail-closed verification of persisted system policy authorizations."""

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import ExecutionPolicyVersion
from .system_authorization_models import (
    SystemPolicyAuthorizationRecord,
    SystemPolicyAuthorizationRevocation,
)


def verify_system_authorization(
    db: Session,
    reference: str,
    expected_policy_digest: str,
    now: datetime | None = None,
) -> dict:
    """Validate an existing authorization without creating one."""

    result = {
        "valid": False,
        "reference": reference,
        "policy_digest": expected_policy_digest,
        "reason": "authorization_unverified",
    }

    if not reference or not expected_policy_digest:
        result["reason"] = "missing_authorization_identity"
        return result

    current_time = now or datetime.now(timezone.utc)

    if current_time.tzinfo is None:
        result["reason"] = "invalid_verification_time"
        return result

    authorization = db.get(SystemPolicyAuthorizationRecord, reference)

    if authorization is None:
        result["reason"] = "authorization_not_found"
        return result

    if authorization.policy_digest != expected_policy_digest:
        result["reason"] = "policy_digest_mismatch"
        return result

    policy = db.execute(
        select(ExecutionPolicyVersion).where(
            ExecutionPolicyVersion.digest == expected_policy_digest
        )
    ).scalar_one_or_none()

    if policy is None:
        result["reason"] = "policy_version_not_found"
        return result

    from .system_policy_integrity import verify_builtin_policy

    integrity = verify_builtin_policy(
        policy.definition,
        expected_policy_digest,
    )

    if not integrity["valid"]:
        result["reason"] = integrity["reason"]
        return result

    if not authorization.provenance or not authorization.provenance.strip():
        result["reason"] = "missing_provenance"
        return result

    valid_from = authorization.valid_from
    valid_until = authorization.valid_until

    if valid_from.tzinfo is None or valid_until.tzinfo is None:
        result["reason"] = "invalid_authorization_timestamps"
        return result

    if not valid_from <= current_time < valid_until:
        result["reason"] = "authorization_outside_validity_window"
        return result

    revocation = db.execute(
        select(SystemPolicyAuthorizationRevocation).where(
            SystemPolicyAuthorizationRevocation.authorization_reference
            == reference
        )
    ).scalar_one_or_none()

    if revocation is not None:
        result["reason"] = "authorization_revoked"
        return result

    from .system_authorization_signing import (
        verify_authorization_signature,
    )

    signature = authorization.provenance

    if not verify_authorization_signature(
        signature,
        authorization.reference,
        authorization.policy_digest,
        valid_from.isoformat(),
        valid_until.isoformat(),
    ):
        result["reason"] = "invalid_system_authorization_signature"
        return result

    result["valid"] = True
    result["reason"] = "authorization_valid"
    return result

    result["valid"] = True
    result["reason"] = "authorization_valid"
    return result
