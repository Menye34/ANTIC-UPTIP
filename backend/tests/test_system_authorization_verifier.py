"""Security regression tests for system authorization verification."""

from unittest.mock import MagicMock

from app.system_authorization_verifier import verify_system_authorization


def test_missing_authorization_reference():
    db = MagicMock()

    result = verify_system_authorization(
        db,
        reference="",
        expected_policy_digest="expected-digest",
    )

    assert result["valid"] is False
    assert result["reason"] == "missing_authorization_identity"
    db.get.assert_not_called()


def test_missing_policy_digest():
    db = MagicMock()

    result = verify_system_authorization(
        db,
        reference="system-auth-001",
        expected_policy_digest="",
    )

    assert result["valid"] is False
    assert result["reason"] == "missing_authorization_identity"
    db.get.assert_not_called()


def test_authorization_not_found():
    db = MagicMock()
    db.get.return_value = None

    result = verify_system_authorization(
        db,
        reference="unknown-authorization",
        expected_policy_digest="expected-digest",
    )

    assert result["valid"] is False
    assert result["reason"] == "authorization_not_found"


def test_policy_digest_mismatch():
    db = MagicMock()
    db.get.return_value.policy_digest = "different-digest"

    result = verify_system_authorization(
        db,
        reference="system-auth-001",
        expected_policy_digest="expected-digest",
    )

    assert result["valid"] is False
    assert result["reason"] == "policy_digest_mismatch"

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.system_policy_catalog import configured_policy
from app.system_policy_integrity import trusted_policy_digest


def _trusted_record_mock():
    now = datetime.now(timezone.utc)
    db = MagicMock()

    authorization = MagicMock()
    authorization.policy_digest = trusted_policy_digest()
    authorization.provenance = "system"
    authorization.valid_from = now - timedelta(hours=1)
    authorization.valid_until = now + timedelta(hours=1)

    db.get.return_value = authorization

    policy = MagicMock()
    policy.definition = configured_policy().model_dump(mode="json")

    db.execute.return_value.scalar_one_or_none.side_effect = [
        policy,
        None,
    ]

    return db, authorization, now


def test_expired_authorization_rejected():
    db, authorization, now = _trusted_record_mock()
    authorization.valid_until = now - timedelta(minutes=1)

    result = verify_system_authorization(
        db,
        "system-auth-001",
        trusted_policy_digest(),
        now=now,
    )

    assert result["valid"] is False
    assert result["reason"] == "authorization_outside_validity_window"


def test_revoked_authorization_rejected():
    db, authorization, now = _trusted_record_mock()

    db.execute.return_value.scalar_one_or_none.side_effect = [
        MagicMock(
            definition=configured_policy().model_dump(mode="json")
        ),
        MagicMock(),
    ]

    result = verify_system_authorization(
        db,
        "system-auth-001",
        trusted_policy_digest(),
        now=now,
    )

    assert result["valid"] is False
    assert result["reason"] == "authorization_revoked"


def test_unverified_issuer_rejected():
    db, authorization, now = _trusted_record_mock()

    result = verify_system_authorization(
        db,
        "system-auth-001",
        trusted_policy_digest(),
        now=now,
    )

    assert result["valid"] is False
    assert result["reason"] == "invalid_system_authorization_signature"


def test_valid_signed_authorization(monkeypatch):
    from app.system_authorization_signing import sign_authorization

    monkeypatch.setenv(
        "UPTIP_SYSTEM_AUTH_SIGNING_KEY",
        "test-only-key-" + "a" * 48,
    )

    db, authorization, now = _trusted_record_mock()
    authorization.reference = "system-auth-001"

    authorization.provenance = sign_authorization(
        authorization.reference,
        authorization.policy_digest,
        authorization.valid_from.isoformat(),
        authorization.valid_until.isoformat(),
    )

    result = verify_system_authorization(
        db,
        authorization.reference,
        trusted_policy_digest(),
        now=now,
    )

    assert result["valid"] is True
    assert result["reason"] == "authorization_valid"


def test_tampered_signature_rejected(monkeypatch):
    from app.system_authorization_signing import sign_authorization

    monkeypatch.setenv(
        "UPTIP_SYSTEM_AUTH_SIGNING_KEY",
        "test-only-key-" + "a" * 48,
    )

    db, authorization, now = _trusted_record_mock()
    authorization.reference = "system-auth-001"

    authorization.provenance = sign_authorization(
        authorization.reference,
        authorization.policy_digest,
        authorization.valid_from.isoformat(),
        authorization.valid_until.isoformat(),
    )

    authorization.provenance = (
        "0" if authorization.provenance[0] != "0" else "1"
    ) + authorization.provenance[1:]

    result = verify_system_authorization(
        db,
        authorization.reference,
        trusted_policy_digest(),
        now=now,
    )

    assert result["valid"] is False
    assert result["reason"] == "invalid_system_authorization_signature"
