"""Synthetic database records for isolated start-evidence provider tests."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.execution_policy import PolicyDefinition
from app.models import (
    Assessment,
    AssessmentTarget,
    AssessmentStartEvidenceRecord,
    BaselineEvaluation,
    ExecutionPolicyApprovalRecord,
    ExecutionPolicyVersion,
    Role,
    User,
)
from test_execution_policy import RULE


def create_evidence_case(db):
    """Create a valid authorization chain without committing."""

    now = datetime.now(timezone.utc)

    role = db.get(Role, 'Security Analyst')
    if role is None:
        db.add(Role(name='Security Analyst'))
        db.flush()

    user = User(
        username=f'evidence-test-{uuid4().hex[:12]}',
        role='Security Analyst',
        password_hash='synthetic-test-hash',
        password_change_required=False,
    )
    db.add(user)
    db.flush()

    assessment = Assessment(
        reference=f'ASM-TEST-{uuid4().hex[:12]}',
        idempotency_key=uuid4(),
        request_fingerprint='a' * 64,
        name='Isolated evidence provider test',
        creator_id=user.id,
        lead_analyst_id=user.id,
    )
    db.add(assessment)
    db.flush()

    target = AssessmentTarget(
        assessment_id=assessment.id,
        original_value='192.0.2.1',
        normalized_value='192.0.2.1',
        kind='IP address',
        scope_status='in_scope',
        classification_reason='synthetic_test',
        scope_revision=0,
    )
    db.add(target)
    db.flush()

    evaluation = BaselineEvaluation(
        assessment_id=assessment.id,
        target_id=target.id,
        profile_key='synthetic-profile',
        fingerprint='b' * 64,
        decision={'synthetic': True},
        trigger='initial',
    )
    db.add(evaluation)
    db.flush()

    definition = PolicyDefinition(
        policy_id=f'evidence-policy-{uuid4().hex[:12]}',
        version=1,
        rules=(RULE,),
    )

    db.add(ExecutionPolicyVersion(
        policy_id=definition.policy_id,
        version=definition.version,
        digest=definition.digest,
        definition=definition.model_dump(mode='json'),
    ))
    db.flush()

    approval = ExecutionPolicyApprovalRecord(
        reference=f'evidence-approval-{uuid4().hex[:12]}',
        policy_digest=definition.digest,
        provenance='Synthetic security test',
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(hours=1),
    )
    db.add(approval)
    db.flush()

    evidence = AssessmentStartEvidenceRecord(
        reference=f'evidence-record-{uuid4().hex[:12]}',
        assessment_id=assessment.id,
        target_id=target.id,
        evaluation_id=evaluation.id,
        evaluation_fingerprint=evaluation.fingerprint,
        approval_reference=approval.reference,
        policy_digest=definition.digest,
        provenance='Synthetic security test',
        valid_from=now - timedelta(minutes=5),
        valid_until=now + timedelta(minutes=30),
        evidence={
            'parameter_digest': 'a' * 64,
            'risk': 'low',
            'verified_prerequisites': ['scope-approved'],
            'requested_units': 1,
            'clear_stop_conditions': ['stop-on-critical'],
            'mandatory_activities': [],
            'prerequisite_completions': [],
        },
    )
    db.add(evidence)
    db.flush()

    return {
        'assessment': assessment,
        'target': target,
        'evaluation': evaluation,
        'definition': definition,
        'approval': approval,
        'evidence': evidence,
    }
