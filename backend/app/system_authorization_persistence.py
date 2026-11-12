"""Persist trusted system-policy authorizations.

No scanner execution or assessment start occurs here.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import ExecutionPolicyVersion
from .system_authorization_issuer import prepare_system_authorization
from .system_authorization_models import SystemPolicyAuthorizationRecord
from .system_policy_integrity import (
    trusted_policy_digest,
    verify_builtin_policy,
)


def create_system_authorization(
    db: Session,
    *,
    validity_minutes: int = 60,
) -> SystemPolicyAuthorizationRecord:
    """Stage a signed authorization for an existing trusted policy."""

    digest = trusted_policy_digest()

    policies = db.execute(
        select(ExecutionPolicyVersion).where(
            ExecutionPolicyVersion.digest == digest
        )
    ).scalars().all()

    if len(policies) != 1:
        raise RuntimeError(
            "Exactly one trusted persisted policy version is required."
        )

    policy = policies[0]

    integrity = verify_builtin_policy(policy.definition, digest)

    if not integrity["valid"]:
        raise RuntimeError(
            f"Policy integrity failed: {integrity['reason']}"
        )

    prepared = prepare_system_authorization(
        validity_minutes=validity_minutes
    )

    if prepared["policy_digest"] != digest:
        raise RuntimeError("Authorization policy digest mismatch.")

    record = SystemPolicyAuthorizationRecord(**prepared)

    db.add(record)
    db.flush()

    # The caller controls the transaction.
    # No automatic commit or scanner dispatch.
    return record
