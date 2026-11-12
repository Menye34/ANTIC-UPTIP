"""Security tests for persisted authorization providers."""

from app.authorization_provider import load_trusted_policy


def test_missing_policy_fails_closed(db):
    """An empty authorization store must never grant policy approval."""
    selection = load_trusted_policy(db)

    assert selection.status == 'unavailable'
    assert selection.code == 'execution_policy_missing'
    assert selection.definition is None
    assert selection.approval is None


def test_expired_policy_approval_fails_closed(db):
    """An expired persisted approval must not authorize a policy."""
    from datetime import datetime, timedelta, timezone

    from app.execution_policy import PolicyDefinition
    from app.models import ExecutionPolicyApprovalRecord, ExecutionPolicyVersion
    from test_execution_policy import RULE

    now = datetime.now(timezone.utc)
    definition = PolicyDefinition(
        policy_id='expired-fixture-policy',
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

    db.add(ExecutionPolicyApprovalRecord(
        reference='expired-fixture-approval',
        policy_digest=definition.digest,
        provenance='Synthetic test approval',
        valid_from=now - timedelta(days=2),
        valid_until=now - timedelta(days=1),
    ))
    db.flush()

    selection = load_trusted_policy(db)

    assert selection.status != 'approved'
    assert selection.definition is None
    assert selection.approval is None


def test_revoked_policy_approval_fails_closed(db):
    """A revoked approval must never produce an approved policy."""
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4

    from app.execution_policy import PolicyDefinition
    from app.models import (
        AuthorizationRecordRevocation,
        ExecutionPolicyApprovalRecord,
        ExecutionPolicyVersion,
    )
    from test_execution_policy import RULE

    now = datetime.now(timezone.utc)
    definition = PolicyDefinition(
        policy_id='revoked-fixture-policy',
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

    db.add(ExecutionPolicyApprovalRecord(
        reference='revoked-fixture-approval',
        policy_digest=definition.digest,
        provenance='Synthetic test approval',
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=1),
    ))
    db.flush()

    db.add(AuthorizationRecordRevocation(
        id=uuid4(),
        approval_reference='revoked-fixture-approval',
        reason='Synthetic test revocation',
        provenance='Security regression test',
    ))
    db.flush()

    selection = load_trusted_policy(db)

    assert selection.status != 'approved'
    assert selection.definition is None
    assert selection.approval is None


def test_multiple_active_approvals_fail_closed(db):
    """Multiple active approvals must not produce an arbitrary selection."""
    from datetime import datetime, timedelta, timezone

    from app.execution_policy import PolicyDefinition
    from app.models import ExecutionPolicyApprovalRecord, ExecutionPolicyVersion
    from test_execution_policy import RULE

    now = datetime.now(timezone.utc)
    definition = PolicyDefinition(
        policy_id='ambiguous-fixture-policy',
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

    for reference in ('ambiguous-approval-one', 'ambiguous-approval-two'):
        db.add(ExecutionPolicyApprovalRecord(
            reference=reference,
            policy_digest=definition.digest,
            provenance='Synthetic test approval',
            valid_from=now - timedelta(hours=1),
            valid_until=now + timedelta(hours=1),
        ))

    db.flush()

    selection = load_trusted_policy(db)

    assert selection.status == 'invalid'
    assert selection.code == 'execution_policy_ambiguous'
    assert selection.definition is None
    assert selection.approval is None


def test_valid_persisted_policy_approval_is_selected(db):
    """One valid governed approval must select its matching policy."""
    from datetime import datetime, timedelta, timezone

    from app.execution_policy import PolicyDefinition
    from app.models import ExecutionPolicyApprovalRecord, ExecutionPolicyVersion
    from test_execution_policy import RULE

    now = datetime.now(timezone.utc)
    definition = PolicyDefinition(
        policy_id='valid-fixture-policy',
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

    db.add(ExecutionPolicyApprovalRecord(
        reference='valid-fixture-approval',
        policy_digest=definition.digest,
        provenance='Synthetic test approval',
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(hours=1),
    ))
    db.flush()

    selection = load_trusted_policy(db)

    assert selection.status == 'approved'
    assert selection.code == 'execution_policy_approved'
    assert selection.definition.policy_id == definition.policy_id
    assert selection.definition.version == definition.version
    assert selection.definition.digest == definition.digest
    assert selection.approval.reference == 'valid-fixture-approval'
    assert selection.approval.provenance == 'Synthetic test approval'
