"""Authenticated signatures for system-managed authorization records."""

import hashlib
import hmac
import json
import os


def authorization_payload(
    reference: str,
    policy_digest: str,
    valid_from: str,
    valid_until: str,
) -> bytes:
    """Canonical authorization identity and validity window."""
    return json.dumps(
        {
            "reference": reference,
            "policy_digest": policy_digest,
            "valid_from": valid_from,
            "valid_until": valid_until,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _signing_key() -> bytes:
    key = os.environ.get("UPTIP_SYSTEM_AUTH_SIGNING_KEY")

    if not key or len(key.encode("utf-8")) < 32:
        raise RuntimeError(
            "A system authorization signing key of at least "
            "32 bytes must be configured."
        )

    return key.encode("utf-8")


def sign_authorization(
    reference: str,
    policy_digest: str,
    valid_from: str,
    valid_until: str,
) -> str:
    """Sign an authorization record using the trusted system key."""
    payload = authorization_payload(
        reference,
        policy_digest,
        valid_from,
        valid_until,
    )

    return hmac.new(
        _signing_key(),
        payload,
        hashlib.sha256,
    ).hexdigest()


def verify_authorization_signature(
    signature: str,
    reference: str,
    policy_digest: str,
    valid_from: str,
    valid_until: str,
) -> bool:
    """Verify an authorization signature without granting execution."""

    if not isinstance(signature, str) or len(signature) != 64:
        return False

    try:
        expected = sign_authorization(
            reference,
            policy_digest,
            valid_from,
            valid_until,
        )
    except RuntimeError:
        return False

    return hmac.compare_digest(expected, signature)
