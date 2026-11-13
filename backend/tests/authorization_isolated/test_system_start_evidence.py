"""Database-backed tests for system-managed Start Assessment evidence."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.models import AssessmentStartEvidenceRecord, ExecutionPolicyVersion
from app.start_evidence_provider import load_trusted_start_evidence
from app.system_authorization_persistence import create_system_authorization
from app.system_policy_catalog import configured_policy
from app.system_policy_integrity import trusted_policy_digest

from evidence_fixtures import create_evidence_case


def test_valid_system_managed_start_evidence(db, monkeypatch):
    """Trusted, signed system authorization must retrieve matching evidence."""
    monkeypatch.setenv(
        "UPTIP_SYSTEM_AUTH_SIGNING_KEY",
        "isolated-system-evidence-test-key-" + "a" * 48,
    )

    case = create_evidence_case(db)

    policy = configured_policy()
    digest = trusted_policy_digest()

    db.add(ExecutionPolicyVersion(
        policy_id=policy.policy_id,
        version=policy.version,
        digest=digest,
        definition=policy.model_dump(mode="json"),
    ))
    db.flush()

    authorization = create_system_authorization(
        db,
        validity_minutes=30,
    )

    now = datetime.now(timezone.utc)

    evidence = AssessmentStartEvidenceRecord(
        reference=f"system-evidence-{uuid4().hex}",
        assessment_id=case["assessment"].id,
        target_id=case["target"].id,
        evaluation_id=case["evaluation"].id,
        evaluation_fingerprint=case["evaluation"].fingerprint,
        approval_reference=None,
        system_authorization_reference=authorization.reference,
        policy_digest=digest,
        provenance="Isolated system authorization test",
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(minutes=20),
        evidence=case["evidence"].evidence,
    )

    db.add(evidence)
    db.flush()

    result = load_trusted_start_evidence(
        db,
        assessment_id=case["assessment"].id,
        target_id=case["target"].id,
        evaluation_id=case["evaluation"].id,
        evaluation_fingerprint=case["evaluation"].fingerprint,
        policy_digest=digest,
        approval_reference=authorization.reference,
    )

    assert result is not None
    assert result.reference == evidence.reference
    assert result.parameter_digest == "a" * 64
    assert result.risk == "low"
    assert result.requested_units == 1


def test_expired_system_authorization_fails_closed(db, monkeypatch):
    """Valid evidence must not override an expired system authorization."""
    monkeypatch.setenv(
        "UPTIP_SYSTEM_AUTH_SIGNING_KEY",
        "isolated-system-evidence-test-key-" + "a" * 48,
    )

    case = create_evidence_case(db)
    policy = configured_policy()
    digest = trusted_policy_digest()

    db.add(ExecutionPolicyVersion(
        policy_id=policy.policy_id,
        version=policy.version,
        digest=digest,
        definition=policy.model_dump(mode="json"),
    ))
    db.flush()

    authorization = create_system_authorization(db, validity_minutes=30)

    # Keep evidence valid beyond the authorization expiration.
    now = datetime.now(timezone.utc)
    future = authorization.valid_until + timedelta(minutes=1)

    evidence = AssessmentStartEvidenceRecord(
        reference=f"expired-auth-evidence-{uuid4().hex}",
        assessment_id=case["assessment"].id,
        target_id=case["target"].id,
        evaluation_id=case["evaluation"].id,
        evaluation_fingerprint=case["evaluation"].fingerprint,
        approval_reference=None,
        system_authorization_reference=authorization.reference,
        policy_digest=digest,
        provenance="Isolated expiration regression test",
        valid_from=now - timedelta(minutes=1),
        valid_until=future + timedelta(minutes=10),
        evidence=case["evidence"].evidence,
    )
    db.add(evidence)
    db.flush()

    # Verify expiration without modifying append-only authorization records.

    from unittest.mock import patch

    with patch("app.start_evidence_provider.datetime") as mocked_datetime:
        mocked_datetime.now.return_value = future

        result = load_trusted_start_evidence(
            db,
            assessment_id=case["assessment"].id,
            target_id=case["target"].id,
            evaluation_id=case["evaluation"].id,
            evaluation_fingerprint=case["evaluation"].fingerprint,
            policy_digest=digest,
            approval_reference=authorization.reference,
        )

    assert result is None


def test_revoked_system_authorization_fails_closed(db, monkeypatch):
    """Revoked authorization must invalidate otherwise valid Start evidence."""
    from app.system_authorization_models import (
        SystemPolicyAuthorizationRevocation,
    )
    from app.system_authorization_verifier import verify_system_authorization

    monkeypatch.setenv(
        "UPTIP_SYSTEM_AUTH_SIGNING_KEY",
        "isolated-system-evidence-test-key-" + "a" * 48,
    )

    case = create_evidence_case(db)
    policy = configured_policy()
    digest = trusted_policy_digest()

    db.add(ExecutionPolicyVersion(
        policy_id=policy.policy_id,
        version=policy.version,
        digest=digest,
        definition=policy.model_dump(mode="json"),
    ))
    db.flush()

    authorization = create_system_authorization(
        db,
        validity_minutes=30,
    )

    now = datetime.now(timezone.utc)

    evidence = AssessmentStartEvidenceRecord(
        reference=f"revoked-auth-evidence-{uuid4().hex}",
        assessment_id=case["assessment"].id,
        target_id=case["target"].id,
        evaluation_id=case["evaluation"].id,
        evaluation_fingerprint=case["evaluation"].fingerprint,
        approval_reference=None,
        system_authorization_reference=authorization.reference,
        policy_digest=digest,
        provenance="Isolated revocation regression test",
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(minutes=20),
        evidence=case["evidence"].evidence,
    )
    db.add(evidence)
    db.flush()

    # Prove the evidence is accepted before revocation.
    before = load_trusted_start_evidence(
        db,
        assessment_id=case["assessment"].id,
        target_id=case["target"].id,
        evaluation_id=case["evaluation"].id,
        evaluation_fingerprint=case["evaluation"].fingerprint,
        policy_digest=digest,
        approval_reference=authorization.reference,
    )
    assert before is not None

    # Insert an append-only authorization revocation.
    db.add(SystemPolicyAuthorizationRevocation(
        authorization_reference=authorization.reference,
        reason="Security regression test revocation",
        provenance="Isolated test fixture",
    ))
    db.flush()

    verification = verify_system_authorization(
        db,
        authorization.reference,
        digest,
    )
    assert verification["valid"] is False
    assert verification["reason"] == "authorization_revoked"

    # The same evidence must now be rejected.
    after = load_trusted_start_evidence(
        db,
        assessment_id=case["assessment"].id,
        target_id=case["target"].id,
        evaluation_id=case["evaluation"].id,
        evaluation_fingerprint=case["evaluation"].fingerprint,
        policy_digest=digest,
        approval_reference=authorization.reference,
    )
    assert after is None


def test_wrong_system_authorization_reference_fails_closed(db, monkeypatch):
    """Evidence must not be accessible using another valid authorization."""
    monkeypatch.setenv(
        "UPTIP_SYSTEM_AUTH_SIGNING_KEY",
        "isolated-system-evidence-test-key-" + "a" * 48,
    )

    case = create_evidence_case(db)
    policy = configured_policy()
    digest = trusted_policy_digest()

    db.add(ExecutionPolicyVersion(
        policy_id=policy.policy_id,
        version=policy.version,
        digest=digest,
        definition=policy.model_dump(mode="json"),
    ))
    db.flush()

    original_authorization = create_system_authorization(
        db, validity_minutes=30,
    )
    other_authorization = create_system_authorization(
        db, validity_minutes=30,
    )

    now = datetime.now(timezone.utc)

    evidence = AssessmentStartEvidenceRecord(
        reference=f"identity-binding-evidence-{uuid4().hex}",
        assessment_id=case["assessment"].id,
        target_id=case["target"].id,
        evaluation_id=case["evaluation"].id,
        evaluation_fingerprint=case["evaluation"].fingerprint,
        approval_reference=None,
        system_authorization_reference=original_authorization.reference,
        policy_digest=digest,
        provenance="Isolated authorization identity test",
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(minutes=20),
        evidence=case["evidence"].evidence,
    )
    db.add(evidence)
    db.flush()

    # The original authorization must retrieve its evidence.
    accepted = load_trusted_start_evidence(
        db,
        assessment_id=case["assessment"].id,
        target_id=case["target"].id,
        evaluation_id=case["evaluation"].id,
        evaluation_fingerprint=case["evaluation"].fingerprint,
        policy_digest=digest,
        approval_reference=original_authorization.reference,
    )
    assert accepted is not None
    assert accepted.reference == evidence.reference

    # Another valid authorization must not retrieve the same evidence.
    rejected = load_trusted_start_evidence(
        db,
        assessment_id=case["assessment"].id,
        target_id=case["target"].id,
        evaluation_id=case["evaluation"].id,
        evaluation_fingerprint=case["evaluation"].fingerprint,
        policy_digest=digest,
        approval_reference=other_authorization.reference,
    )
    assert rejected is None
