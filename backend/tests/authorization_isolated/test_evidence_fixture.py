"""Verify synthetic evidence fixtures using the isolated test database."""

from evidence_fixtures import create_evidence_case


def test_evidence_fixture_database_relationships(db):
    case = create_evidence_case(db)

    assessment = case['assessment']
    target = case['target']
    evaluation = case['evaluation']
    approval = case['approval']
    evidence = case['evidence']

    assert target.assessment_id == assessment.id
    assert evaluation.assessment_id == assessment.id
    assert evaluation.target_id == target.id

    assert evidence.assessment_id == assessment.id
    assert evidence.target_id == target.id
    assert evidence.evaluation_id == evaluation.id
    assert evidence.evaluation_fingerprint == evaluation.fingerprint

    assert evidence.policy_digest == case['definition'].digest
    assert evidence.approval_reference == approval.reference
