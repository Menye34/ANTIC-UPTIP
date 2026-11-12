"""Verify persisted system policies against trusted application definitions."""

import hashlib
import hmac
import json

from pydantic import ValidationError

from .execution_policy import PolicyDefinition
from .system_policy_catalog import configured_policy


def canonical_policy_bytes(definition: PolicyDefinition) -> bytes:
    """Produce deterministic policy serialization."""
    return json.dumps(
        definition.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def trusted_policy_digest() -> str:
    """Calculate the digest of the built-in system policy."""
    return hashlib.sha256(
        canonical_policy_bytes(configured_policy())
    ).hexdigest()


def verify_builtin_policy(
    stored_definition,
    expected_digest: str,
) -> dict:
    """Fail closed if a persisted policy differs from the built-in policy."""

    result = {
        "valid": False,
        "reason": "policy_integrity_unverified",
    }

    if not isinstance(expected_digest, str) or len(expected_digest) != 64:
        result["reason"] = "invalid_policy_digest"
        return result

    try:
        definition = PolicyDefinition.model_validate_json(
            json.dumps(stored_definition)
        )
    except (ValidationError, TypeError, ValueError):
        result["reason"] = "invalid_policy_definition"
        return result

    actual_bytes = canonical_policy_bytes(definition)
    trusted_bytes = canonical_policy_bytes(configured_policy())

    if not hmac.compare_digest(actual_bytes, trusted_bytes):
        result["reason"] = "builtin_policy_mismatch"
        return result

    actual_digest = hashlib.sha256(actual_bytes).hexdigest()

    if not hmac.compare_digest(actual_digest, expected_digest):
        result["reason"] = "policy_digest_mismatch"
        return result

    result["valid"] = True
    result["reason"] = "builtin_policy_verified"
    return result
