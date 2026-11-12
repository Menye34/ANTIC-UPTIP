"""Security regression tests for persisted start evidence."""

from app.start_evidence_provider import load_trusted_start_evidence
from evidence_fixtures import create_evidence_case


def retrieve(db, case, **overrides):
    """Load evidence using the exact authorization binding."""
    arguments = {
        'assessment_id': case['assessment'].id,
        'target_id': case['target'].id,
        'evaluation_id': case['evaluation'].id,
        'evaluation_fingerprint': case['evaluation'].fingerprint,
        'policy_digest': case['definition'].digest,
        'approval_reference': case['approval'].reference,
    }
    arguments.update(overrides)
    return load_trusted_start_evidence(db, **arguments)


def test_valid_persisted_evidence_is_selected(db):
    """One valid governed evidence record must be retrievable."""
    case = create_evidence_case(db)

    result = retrieve(db, case)

    assert result is not None
    assert result.reference == case['evidence'].reference
    assert result.parameter_digest == 'a' * 64
    assert result.risk == 'low'
    assert result.requested_units == 1
    assert result.verified_prerequisites == frozenset({'scope-approved'})
    assert result.clear_stop_conditions == frozenset({'stop-on-critical'})
    assert result.mandatory_activities == frozenset()
    assert result.prerequisite_completions == ()


def test_missing_evidence_fails_closed(db):
    from uuid import uuid4

    assert load_trusted_start_evidence(
        db,
        assessment_id=uuid4(),
        target_id=uuid4(),
        evaluation_id=uuid4(),
        evaluation_fingerprint='b' * 64,
        policy_digest='a' * 64,
        approval_reference='nonexistent-approval',
    ) is None


def test_incorrect_authorization_bindings_fail_closed(db):
    from uuid import uuid4

    case = create_evidence_case(db)

    for changed in (
        {'assessment_id': uuid4()},
        {'target_id': uuid4()},
        {'evaluation_id': uuid4()},
        {'evaluation_fingerprint': 'c' * 64},
        {'policy_digest': 'd' * 64},
        {'approval_reference': 'incorrect-approval'},
    ):
        assert retrieve(db, case, **changed) is None


def test_expired_evidence_fails_closed(db):
    from datetime import datetime, timedelta, timezone
    from app.models import AssessmentStartEvidenceRecord

    case = create_evidence_case(db)
    original = case['evidence']

    expired = AssessmentStartEvidenceRecord(
        reference='expired-' + original.reference,
        assessment_id=original.assessment_id,
        target_id=original.target_id,
        evaluation_id=original.evaluation_id,
        evaluation_fingerprint=original.evaluation_fingerprint,
        approval_reference=original.approval_reference,
        policy_digest=original.policy_digest,
        provenance='Synthetic expired evidence',
        valid_from=datetime.now(timezone.utc) - timedelta(days=2),
        valid_until=datetime.now(timezone.utc) - timedelta(days=1),
        evidence=original.evidence,
    )
    db.add(expired)
    db.flush()

    assert retrieve(db, case) is not None


def test_revoked_evidence_fails_closed(db):
    from uuid import uuid4
    from app.models import AuthorizationRecordRevocation

    case = create_evidence_case(db)

    db.add(AuthorizationRecordRevocation(
        id=uuid4(),
        evidence_reference=case['evidence'].reference,
        reason='Synthetic evidence revocation',
        provenance='Security regression test',
    ))
    db.flush()

    assert retrieve(db, case) is None


def test_revoked_policy_approval_fails_closed(db):
    from uuid import uuid4
    from app.models import AuthorizationRecordRevocation

    case = create_evidence_case(db)

    db.add(AuthorizationRecordRevocation(
        id=uuid4(),
        approval_reference=case['approval'].reference,
        reason='Synthetic policy approval revocation',
        provenance='Security regression test',
    ))
    db.flush()

    assert retrieve(db, case) is None


def test_only_expired_evidence_fails_closed(db):
    from datetime import datetime, timedelta, timezone
    from app.models import AssessmentStartEvidenceRecord

    case = create_evidence_case(db)
    original = case['evidence']

    db.add(AssessmentStartEvidenceRecord(
        reference='expired-only-' + original.reference,
        assessment_id=original.assessment_id,
        target_id=original.target_id,
        evaluation_id=original.evaluation_id,
        evaluation_fingerprint=original.evaluation_fingerprint,
        approval_reference=original.approval_reference,
        policy_digest=original.policy_digest,
        provenance='Synthetic expired evidence',
        valid_from=datetime.now(timezone.utc) - timedelta(days=2),
        valid_until=datetime.now(timezone.utc) - timedelta(days=1),
        evidence=original.evidence,
    ))
    db.flush()

    from app.models import AuthorizationRecordRevocation
    from uuid import uuid4

    db.add(AuthorizationRecordRevocation(
        id=uuid4(),
        evidence_reference=original.reference,
        reason='Exclude original valid evidence',
        provenance='Security regression test',
    ))
    db.flush()

    assert retrieve(db, case) is None


def test_malformed_evidence_fails_closed(db):
    from app.models import AssessmentStartEvidenceRecord
    from uuid import uuid4

    case = create_evidence_case(db)
    original = case['evidence']

    db.add(AssessmentStartEvidenceRecord(
        reference='malformed-' + uuid4().hex,
        assessment_id=original.assessment_id,
        target_id=original.target_id,
        evaluation_id=original.evaluation_id,
        evaluation_fingerprint=original.evaluation_fingerprint,
        approval_reference=original.approval_reference,
        policy_digest=original.policy_digest,
        provenance='Synthetic malformed evidence',
        valid_from=original.valid_from,
        valid_until=original.valid_until,
        evidence={'risk': 'low'},
    ))
    db.flush()

    assert retrieve(db, case) is None


def test_ambiguous_valid_evidence_fails_closed(db):
    from app.models import AssessmentStartEvidenceRecord
    from uuid import uuid4

    case = create_evidence_case(db)
    original = case['evidence']

    db.add(AssessmentStartEvidenceRecord(
        reference='duplicate-' + uuid4().hex,
        assessment_id=original.assessment_id,
        target_id=original.target_id,
        evaluation_id=original.evaluation_id,
        evaluation_fingerprint=original.evaluation_fingerprint,
        approval_reference=original.approval_reference,
        policy_digest=original.policy_digest,
        provenance='Synthetic duplicate evidence',
        valid_from=original.valid_from,
        valid_until=original.valid_until,
        evidence=original.evidence,
    ))
    db.flush()

    assert retrieve(db, case) is None


def test_only_malformed_evidence_fails_closed(db):
    """Malformed evidence must fail closed even without ambiguity."""
    from uuid import uuid4

    from app.models import (
        AssessmentStartEvidenceRecord,
        AuthorizationRecordRevocation,
    )

    case = create_evidence_case(db)
    original = case['evidence']

    db.add(AssessmentStartEvidenceRecord(
        reference='malformed-only-' + uuid4().hex,
        assessment_id=original.assessment_id,
        target_id=original.target_id,
        evaluation_id=original.evaluation_id,
        evaluation_fingerprint=original.evaluation_fingerprint,
        approval_reference=original.approval_reference,
        policy_digest=original.policy_digest,
        provenance='Synthetic malformed evidence',
        valid_from=original.valid_from,
        valid_until=original.valid_until,
        evidence={'risk': 'low'},
    ))

    db.add(AuthorizationRecordRevocation(
        id=uuid4(),
        evidence_reference=original.reference,
        reason='Exclude original valid evidence',
        provenance='Security regression test',
    ))

    db.flush()

    assert retrieve(db, case) is None
