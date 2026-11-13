"""Security tests for persisted authorization providers."""

import pytest

from app.authorization_provider import load_trusted_policy
from app.system_policy_catalog import configured_policy
from app.system_policy_integrity import trusted_policy_digest


def assert_configured_without_authorization(selection):
    """Configuration identifies an envelope; it does not supply approval."""
    expected = configured_policy()
    assert selection.status == 'configured'
    assert selection.code == 'system_policy_configured'
    assert selection.definition == expected
    assert selection.definition.digest == expected.digest == trusted_policy_digest()
    assert selection.approval is None


def test_missing_policy_fails_closed(db):
    """An empty authorization store must never grant policy approval."""
    selection = load_trusted_policy(db)

    assert_configured_without_authorization(selection)


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

    assert_configured_without_authorization(selection)
    assert selection.definition.policy_id != definition.policy_id
    assert selection.definition.digest != definition.digest


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

    assert_configured_without_authorization(selection)
    assert selection.definition.policy_id != definition.policy_id
    assert selection.definition.digest != definition.digest


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


def test_unavailable_policy_configuration_fails_closed(db, monkeypatch):
    from app import system_policy_catalog

    monkeypatch.setattr(system_policy_catalog, 'configured_policy', lambda: None)
    selection = load_trusted_policy(db)

    assert selection.status == 'unavailable'
    assert selection.code == 'execution_policy_missing'
    assert selection.definition is None
    assert selection.approval is None


def test_real_configured_policy_cannot_authorize_dispatch(db, monkeypatch):
    """Exercise the actual provider, rather than inventing a policy selection."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from app import nmap_dispatch_authorization as dispatch

    selection = load_trusted_policy(db)
    assert_configured_without_authorization(selection)
    request_db = MagicMock()
    request_db.scalar.side_effect = [
        SimpleNamespace(status='Queued', tool='Nmap', activity='Network Discovery',
                        assessment_id='assessment', authorization_id='authorization'),
        SimpleNamespace(status='Testing'),
        SimpleNamespace(snapshot={}),
    ]
    monkeypatch.setattr(dispatch, 'load_trusted_policy', lambda _: load_trusted_policy(db))
    result = dispatch.verify_nmap_dispatch_authorization(
        request_db, execution_request_id='queued-request',
    )
    assert result.authorized is False
    assert result.reason_code == 'trusted_policy_not_approved'


def signed_system_case(db, monkeypatch, *, invalid=None):
    """Real signatures and persisted JSON; never a production authorization."""
    from datetime import datetime, timedelta, timezone
    from app.models import ExecutionPolicyVersion
    from app.system_authorization_models import SystemPolicyAuthorizationRecord
    from app.system_authorization_issuer import prepare_system_authorization
    from app.system_authorization_signing import sign_authorization

    monkeypatch.setenv('UPTIP_SYSTEM_AUTH_SIGNING_KEY', 'synthetic-provider-test-only-' + 'x' * 48)
    definition = configured_policy()
    document = definition.model_dump(mode='json')
    digest = definition.digest
    if invalid == 'definition':
        document['rules'][0]['max_units'] = 2
    if invalid == 'digest':
        digest = 'f' * 64
    # Core INSERT models a corrupt persisted document without disabling any
    # ORM validation hooks or append-only database protections.
    db.execute(ExecutionPolicyVersion.__table__.insert().values(
        policy_id=definition.policy_id, version=1, digest=digest, definition=document))
    db.flush()
    prepared = prepare_system_authorization(validity_minutes=30)
    if invalid == 'expired':
        now = datetime.now(timezone.utc)
        prepared['valid_from'] = now - timedelta(hours=2)
        prepared['valid_until'] = now - timedelta(hours=1)
    prepared['policy_digest'] = digest
    prepared['provenance'] = sign_authorization(
        prepared['reference'], digest, prepared['valid_from'].isoformat(),
        prepared['valid_until'].isoformat())
    if invalid == 'signature':
        prepared['provenance'] = '0' * 64
    record = SystemPolicyAuthorizationRecord(**prepared)
    db.add(record)
    db.flush()
    return definition, record


def test_valid_signed_system_authorization_selects_exact_json_policy(db, monkeypatch):
    definition, record = signed_system_case(db, monkeypatch)
    db.expire_all()
    selection = load_trusted_policy(db)
    assert selection.status == 'approved'
    assert selection.definition == definition
    assert selection.definition.digest == trusted_policy_digest()
    assert selection.approval.reference == record.reference


@pytest.mark.parametrize('invalid', ['expired', 'revoked', 'signature', 'definition', 'digest'])
def test_invalid_signed_system_authorization_is_never_selected(db, monkeypatch, invalid):
    from app.system_authorization_models import SystemPolicyAuthorizationRevocation
    _, record = signed_system_case(db, monkeypatch, invalid=invalid)
    if invalid == 'revoked':
        db.add(SystemPolicyAuthorizationRevocation(authorization_reference=record.reference,
               reason='Synthetic revocation', provenance='Test only'))
        db.flush()
    selection = load_trusted_policy(db)
    assert selection.status == 'invalid'
    assert selection.code == 'system_authorization_unverified'
    assert selection.approval is None
    assert selection.definition is None


def test_multiple_valid_signed_system_authorizations_are_ambiguous(db, monkeypatch):
    from app.system_authorization_persistence import create_system_authorization
    from app.system_authorization_verifier import verify_system_authorization
    definition, first = signed_system_case(db, monkeypatch)
    second = create_system_authorization(db, validity_minutes=30)
    db.expire_all()
    for record in (first, second):
        verification = verify_system_authorization(db, record.reference, definition.digest)
        assert verification['valid'], verification['reason']
    selection = load_trusted_policy(db)
    assert selection.status == 'invalid'
    assert selection.code == 'system_authorization_ambiguous'
    assert selection.approval is None


@pytest.mark.parametrize('zone', ['UTC', 'Africa/Douala'])
def test_persisted_signed_authorization_is_independent_of_database_timezone(db, monkeypatch, zone):
    from sqlalchemy import text
    definition, record = signed_system_case(db, monkeypatch)
    reference = record.reference
    # Transaction-local setting affects only this disposable test transaction.
    db.execute(text("SELECT set_config('TimeZone', :zone, true)"), {'zone': zone})
    db.expire_all()
    selection = load_trusted_policy(db)
    assert selection.status == 'approved'
    assert selection.definition == definition
    assert selection.approval.reference == reference
    assert selection.definition.digest == trusted_policy_digest()
