"""Prepare signed authorization records for trusted built-in policies.

This module does not grant scanner execution permission.
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from .system_authorization_signing import sign_authorization
from .system_policy_integrity import (
    trusted_policy_digest,
    verify_builtin_policy,
)
from .system_policy_catalog import configured_policy


def prepare_system_authorization(
    *,
    validity_minutes: int = 60,
    now: datetime | None = None,
) -> dict:
    """Prepare an authorization for the exact built-in policy."""

    if (
        type(validity_minutes) is not int
        or not 1 <= validity_minutes <= 60
    ):
        raise ValueError("Validity must be between 1 and 60 minutes.")

    current_time = now or datetime.now(timezone.utc)

    if current_time.tzinfo is None:
        raise ValueError("Authorization time must include a timezone.")

    current_time = current_time.astimezone(timezone.utc)

    policy = configured_policy()
    digest = trusted_policy_digest()

    integrity = verify_builtin_policy(
        policy.model_dump(mode="json"),
        digest,
    )

    if not integrity["valid"]:
        raise RuntimeError("Built-in policy integrity verification failed.")

    reference = f"system-auth-{uuid4().hex}"
    valid_until = current_time + timedelta(minutes=validity_minutes)

    signature = sign_authorization(
        reference,
        digest,
        current_time.isoformat(),
        valid_until.isoformat(),
    )

    return {
        "reference": reference,
        "policy_digest": digest,
        "provenance": signature,
        "valid_from": current_time,
        "valid_until": valid_until,
    }
