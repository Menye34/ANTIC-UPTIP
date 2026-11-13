"""Fail-closed tests for the Nmap dispatch authorization foundation."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from app.nmap_dispatch_authorization import (
    verify_nmap_dispatch_authorization,
)


def test_missing_execution_request_is_denied():
    db = MagicMock()
    db.scalar.return_value = None

    result = verify_nmap_dispatch_authorization(
        db, execution_request_id="missing"
    )

    assert result.authorized is False
    assert result.reason_code == "execution_request_not_found"


def test_nonqueued_execution_request_is_denied():
    db = MagicMock()
    db.scalar.return_value = SimpleNamespace(
        status="Running",
        tool="Nmap",
        activity="Network Discovery",
    )

    result = verify_nmap_dispatch_authorization(
        db, execution_request_id="running"
    )

    assert result.authorized is False
    assert result.reason_code == "execution_request_not_queued"


def test_unsupported_activity_is_denied():
    db = MagicMock()
    db.scalar.return_value = SimpleNamespace(
        status="Queued",
        tool="Nmap",
        activity="Port Scanning",
    )

    result = verify_nmap_dispatch_authorization(
        db, execution_request_id="unsupported"
    )

    assert result.authorized is False
    assert result.reason_code == "unsupported_execution_activity"


def test_assessment_not_in_testing_is_denied():
    db = MagicMock()
    db.scalar.side_effect = [
        SimpleNamespace(
            status="Queued",
            tool="Nmap",
            activity="Network Discovery",
            assessment_id="assessment-1",
        ),
        SimpleNamespace(status="Draft"),
    ]

    result = verify_nmap_dispatch_authorization(
        db, execution_request_id="execution-1"
    )

    assert result.authorized is False
    assert result.reason_code == "assessment_not_in_testing"


def test_missing_start_authorization_is_denied():
    db = MagicMock()
    db.scalar.side_effect = [
        SimpleNamespace(
            status="Queued",
            tool="Nmap",
            activity="Network Discovery",
            assessment_id="assessment-1",
            authorization_id="authorization-1",
        ),
        SimpleNamespace(status="Testing"),
        None,
    ]

    result = verify_nmap_dispatch_authorization(
        db, execution_request_id="execution-1"
    )

    assert result.authorized is False
    assert result.reason_code == "start_authorization_not_found"


def test_configured_policy_without_approval_is_denied(monkeypatch):
    from app import nmap_dispatch_authorization as module

    db = MagicMock()
    db.scalar.side_effect = [
        SimpleNamespace(
            status="Queued",
            tool="Nmap",
            activity="Network Discovery",
            assessment_id="assessment-1",
            authorization_id="authorization-1",
        ),
        SimpleNamespace(status="Testing"),
        SimpleNamespace(
            snapshot={"policy": {"digest": "digest-123"}}
        ),
    ]

    monkeypatch.setattr(
        module,
        "load_trusted_policy",
        lambda db: SimpleNamespace(
            status="configured",
            definition=SimpleNamespace(digest="digest-123"),
            approval=None,
        ),
    )

    result = module.verify_nmap_dispatch_authorization(
        db, execution_request_id="execution-1"
    )

    assert result.authorized is False
    assert result.reason_code == "trusted_policy_not_approved"


def test_start_policy_digest_mismatch_is_denied(monkeypatch):
    from app import nmap_dispatch_authorization as module

    db = MagicMock()
    db.scalar.side_effect = [
        SimpleNamespace(
            status="Queued",
            tool="Nmap",
            activity="Network Discovery",
            assessment_id="assessment-1",
            authorization_id="authorization-1",
        ),
        SimpleNamespace(status="Testing"),
        make_integrity_authorization(
            {"policy": {"digest": "original-digest"}}
        ),
    ]

    monkeypatch.setattr(
        module,
        "load_trusted_policy",
        lambda db: SimpleNamespace(
            status="approved",
            definition=SimpleNamespace(digest="different-digest"),
            approval=SimpleNamespace(reference="authorization-ref"),
        ),
    )

    result = module.verify_nmap_dispatch_authorization(
        db, execution_request_id="execution-1"
    )

    assert result.authorized is False
    assert result.reason_code == "start_policy_digest_mismatch"


def make_binding_fixture():
    from copy import deepcopy

    activity = {
        "target_id": "target-1",
        "profile_id": "nmap-discovery",
        "version": 1,
        "tool": "Nmap",
        "activity": "Network Discovery",
        "status": "resolved",
        "policy": {"disposition": "preauthorized"},
        "safety_evidence": {
            "parameter_digest": "digest-123",
            "reference": "evidence-123",
        },
        "evaluation_fingerprint": "fingerprint-123",
        "profile_digest": "profile-digest-123",
    }

    snapshot = {
        "assessment_id": "assessment-1",
        "targets": [
            {"target_id": "target-1", "value": "192.0.2.10"}
        ],
        "eligible_activities": [deepcopy(activity)],
    }

    request = SimpleNamespace(
        assessment_id="assessment-1",
        target_id="target-1",
        profile_id="nmap-discovery",
        profile_version=1,
        tool="Nmap",
        activity="Network Discovery",
        authorized_activity={
            **deepcopy(activity),
            "target_value": "192.0.2.10",
        },
    )

    return request, snapshot


def test_valid_snapshot_binding_remains_dispatch_blocked():
    from app.nmap_dispatch_authorization import (
        verify_execution_snapshot_binding,
    )

    request, snapshot = make_binding_fixture()

    result = verify_execution_snapshot_binding(request, snapshot)

    assert result.authorized is False
    assert result.reason_code == (
        "execution_snapshot_binding_verified_dispatch_pending"
    )


def test_mismatched_profile_is_denied():
    from app.nmap_dispatch_authorization import (
        verify_execution_snapshot_binding,
    )

    request, snapshot = make_binding_fixture()
    request.profile_id = "different-profile"

    result = verify_execution_snapshot_binding(request, snapshot)

    assert result.authorized is False
    assert result.reason_code == "execution_activity_binding_mismatch"


def test_modified_queued_evidence_is_denied():
    from app.nmap_dispatch_authorization import (
        verify_execution_snapshot_binding,
    )

    request, snapshot = make_binding_fixture()
    request.authorized_activity["safety_evidence"][
        "parameter_digest"
    ] = "modified-digest"

    result = verify_execution_snapshot_binding(request, snapshot)

    assert result.authorized is False
    assert result.reason_code == "queued_activity_evidence_mismatch"


def test_missing_eligible_activity_is_denied():
    from app.nmap_dispatch_authorization import (
        verify_execution_snapshot_binding,
    )

    request, snapshot = make_binding_fixture()
    snapshot["eligible_activities"] = []

    result = verify_execution_snapshot_binding(request, snapshot)

    assert result.authorized is False
    assert result.reason_code == "execution_activity_binding_mismatch"


def test_main_dispatch_gate_rejects_modified_queued_evidence(monkeypatch):
    from app import nmap_dispatch_authorization as module

    request, snapshot = make_binding_fixture()

    request.status = "Queued"
    request.authorization_id = "authorization-1"

    # Simulate modification after the request was queued.
    request.authorized_activity["safety_evidence"][
        "parameter_digest"
    ] = "tampered-digest"

    snapshot["policy"] = {
        "digest": "policy-digest",
        "approval_reference": "system-auth-ref",
    }

    db = MagicMock()
    db.scalar.side_effect = [
        request,
        SimpleNamespace(status="Testing"),
        make_integrity_authorization(snapshot),
    ]

    monkeypatch.setattr(
        module,
        "load_trusted_policy",
        lambda db: SimpleNamespace(
            status="approved",
            definition=SimpleNamespace(digest="policy-digest"),
            approval={
                "reference": "system-auth-ref",
                "digest": "policy-digest",
            },
        ),
    )


    from app import system_authorization_verifier

    monkeypatch.setattr(
        system_authorization_verifier,
        "verify_system_authorization",
        lambda db, reference, digest: {
            "valid": (
                reference == "system-auth-ref"
                and digest == "policy-digest"
            ),
            "reason": "authorization_valid",
        },
    )

    result = module.verify_nmap_dispatch_authorization(
        db,
        execution_request_id="execution-1",
    )

    assert result.authorized is False
    assert result.reason_code == "queued_activity_evidence_mismatch"


def test_current_scope_target_binding_scenarios():
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from app.nmap_dispatch_authorization import verify_current_scope_target

    request, snapshot = make_binding_fixture()
    from app.baseline_catalog import fingerprint
    from app import target_scope
    from unittest.mock import patch

    boundaries = [("192.0.2.0/24", "network")]

    snapshot["scope_revision"] = 3
    snapshot["scope_digest"] = fingerprint(
        sorted(map(list, boundaries))
    )
    snapshot["targets"][0].update({
        "kind": "IP address",
        "revision": 2,
        "scope_status": "in_scope",
    })

    assessment = SimpleNamespace(
        id="assessment-1",
        scope_revision=3,
    )

    target = SimpleNamespace(
        normalized_value="192.0.2.10",
        kind="IP address",
        scope_status="in_scope",
        scope_revision=3,
        revision=2,
    )

    db = MagicMock()
    db.scalar.return_value = target

    scope_patch = patch.object(
        target_scope,
        "scope_entries",
        return_value=boundaries,
    )
    scope_patch.start()
    try:
        _run_scope_target_scenarios(
            db, assessment, request, snapshot, target
        )
    finally:
        scope_patch.stop()


def _run_scope_target_scenarios(
    db, assessment, request, snapshot, target
):
    from app.nmap_dispatch_authorization import verify_current_scope_target

    result = verify_current_scope_target(
        db, assessment, request, snapshot
    )
    assert result.authorized is False
    assert result.reason_code == (
        "current_scope_target_binding_verified_dispatch_pending"
    )

    assessment.scope_revision = 4
    result = verify_current_scope_target(
        db, assessment, request, snapshot
    )
    assert result.reason_code == "assessment_scope_revision_changed"

    assessment.scope_revision = 3
    db.scalar.return_value = None
    result = verify_current_scope_target(
        db, assessment, request, snapshot
    )
    assert result.reason_code == "current_target_not_found"

    db.scalar.return_value = target
    target.scope_status = "out_of_scope"
    result = verify_current_scope_target(
        db, assessment, request, snapshot
    )
    assert result.reason_code == "target_not_in_scope"

    target.scope_status = "in_scope"
    target.revision = 3
    result = verify_current_scope_target(
        db, assessment, request, snapshot
    )
    assert result.reason_code == "target_revision_changed"

    target.revision = 2
    target.normalized_value = "192.0.2.20"
    result = verify_current_scope_target(
        db, assessment, request, snapshot
    )
    assert result.reason_code == "target_identity_changed"


def test_main_dispatch_gate_rejects_changed_scope_revision(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from app import nmap_dispatch_authorization as module

    request, snapshot = make_binding_fixture()

    request.status = "Queued"
    request.authorization_id = "authorization-1"

    snapshot["policy"] = {
        "digest": "policy-digest",
        "approval_reference": "system-auth-ref",
    }
    snapshot["scope_revision"] = 3
    snapshot["targets"][0].update({
        "kind": "IP address",
        "revision": 2,
        "scope_status": "in_scope",
    })

    # Scope changed after Start Assessment.
    assessment = SimpleNamespace(
        status="Testing",
        scope_revision=4,
    )

    db = MagicMock()
    db.scalar.side_effect = [
        request,
        assessment,
        make_integrity_authorization(snapshot),
    ]

    monkeypatch.setattr(
        module,
        "load_trusted_policy",
        lambda db: SimpleNamespace(
            status="approved",
            definition=SimpleNamespace(digest="policy-digest"),
            approval={
                "reference": "system-auth-ref",
                "digest": "policy-digest",
            },
        ),
    )

    from app import system_authorization_verifier

    monkeypatch.setattr(
        system_authorization_verifier,
        "verify_system_authorization",
        lambda db, reference, digest: {
            "valid": (
                reference == "system-auth-ref"
                and digest == "policy-digest"
            ),
            "reason": "authorization_valid",
        },
    )

    result = module.verify_nmap_dispatch_authorization(
        db,
        execution_request_id="execution-1",
    )

    assert result.authorized is False
    assert result.reason_code == "assessment_scope_revision_changed"


def test_current_scope_digest_verification(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from app import nmap_dispatch_authorization as module
    from app.baseline_catalog import fingerprint
    from app import target_scope

    request, snapshot = make_binding_fixture()

    assessment = SimpleNamespace(
        id="assessment-1",
        scope_revision=3,
    )

    boundaries = [("192.0.2.0/24", "network")]
    snapshot["scope_revision"] = 3
    snapshot["scope_digest"] = fingerprint(
        sorted(map(list, boundaries))
    )

    snapshot["targets"][0].update({
        "kind": "IP address",
        "revision": 2,
        "scope_status": "in_scope",
    })

    target = SimpleNamespace(
        normalized_value="192.0.2.10",
        kind="IP address",
        scope_status="in_scope",
        scope_revision=3,
        revision=2,
    )

    db = MagicMock()
    db.scalar.return_value = target

    monkeypatch.setattr(
        target_scope,
        "scope_entries",
        lambda db, assessment_id: boundaries,
    )

    result = module.verify_current_scope_target(
        db, assessment, request, snapshot
    )

    assert result.authorized is False
    assert result.reason_code == (
        "current_scope_target_binding_verified_dispatch_pending"
    )

    # Change scope contents without changing revision.
    monkeypatch.setattr(
        target_scope,
        "scope_entries",
        lambda db, assessment_id: [
            ("198.51.100.0/24", "network")
        ],
    )

    result = module.verify_current_scope_target(
        db, assessment, request, snapshot
    )

    assert result.authorized is False
    assert result.reason_code == "assessment_scope_digest_changed"


def test_main_dispatch_gate_rejects_changed_scope_digest(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from app import nmap_dispatch_authorization as module
    from app import target_scope
    from app.baseline_catalog import fingerprint

    request, snapshot = make_binding_fixture()
    request.status = "Queued"
    request.authorization_id = "authorization-1"

    original_boundaries = [("192.0.2.0/24", "network")]
    changed_boundaries = [("198.51.100.0/24", "network")]

    snapshot["scope_revision"] = 3
    snapshot["scope_digest"] = fingerprint(
        sorted(map(list, original_boundaries))
    )
    snapshot["policy"] = {
        "digest": "policy-digest",
        "approval_reference": "system-auth-ref",
    }

    assessment = SimpleNamespace(
        id="assessment-1",
        status="Testing",
        scope_revision=3,
    )

    db = MagicMock()
    db.scalar.side_effect = [
        request,
        assessment,
        make_integrity_authorization(snapshot),
    ]

    monkeypatch.setattr(
        module,
        "load_trusted_policy",
        lambda db: SimpleNamespace(
            status="approved",
            definition=SimpleNamespace(digest="policy-digest"),
            approval={
                "reference": "system-auth-ref",
                "digest": "policy-digest",
            },
        ),
    )

    monkeypatch.setattr(
        target_scope,
        "scope_entries",
        lambda db, assessment_id: changed_boundaries,
    )

    from app import system_authorization_verifier

    monkeypatch.setattr(
        system_authorization_verifier,
        "verify_system_authorization",
        lambda db, reference, digest: {
            "valid": (
                reference == "system-auth-ref"
                and digest == "policy-digest"
            ),
            "reason": "authorization_valid",
        },
    )

    result = module.verify_nmap_dispatch_authorization(
        db,
        execution_request_id="execution-1",
    )

    assert result.authorized is False
    assert result.reason_code == "assessment_scope_digest_changed"


def test_start_snapshot_integrity_scenarios():
    from copy import deepcopy
    from types import SimpleNamespace

    from app.assessment_start import SNAPSHOT_VERSION
    from app.baseline_catalog import fingerprint
    from app.nmap_dispatch_authorization import (
        verify_start_snapshot_integrity,
    )

    request = SimpleNamespace(assessment_id="assessment-1")

    snapshot = {
        "schema_version": SNAPSHOT_VERSION,
        "assessment_id": "assessment-1",
        "lifecycle_status": "Draft",
        "mode": "full",
        "targets": [{"target_id": "target-1"}],
    }

    authorization = SimpleNamespace(
        assessment_id="assessment-1",
        snapshot_version=SNAPSHOT_VERSION,
        mode="full",
        snapshot_digest=fingerprint(snapshot),
    )

    def check(snap, auth, expected):
        result = verify_start_snapshot_integrity(
            auth, request, snap
        )
        assert result.authorized is False
        assert result.reason_code == expected

    check(
        snapshot,
        authorization,
        "start_snapshot_integrity_verified",
    )

    tampered = deepcopy(snapshot)
    tampered["targets"][0]["target_id"] = "target-2"
    check(
        tampered,
        authorization,
        "start_snapshot_integrity_mismatch",
    )

    wrong_version = deepcopy(snapshot)
    wrong_version["schema_version"] = 999
    check(
        wrong_version,
        authorization,
        "start_snapshot_version_mismatch",
    )

    wrong_assessment = deepcopy(snapshot)
    wrong_assessment["assessment_id"] = "assessment-2"
    check(
        wrong_assessment,
        authorization,
        "start_snapshot_assessment_mismatch",
    )

    wrong_mode = deepcopy(snapshot)
    wrong_mode["mode"] = "partial"
    check(
        wrong_mode,
        authorization,
        "start_snapshot_mode_mismatch",
    )

    wrong_lifecycle = deepcopy(snapshot)
    wrong_lifecycle["lifecycle_status"] = "Testing"
    check(
        wrong_lifecycle,
        authorization,
        "start_snapshot_lifecycle_mismatch",
    )

    missing_digest = SimpleNamespace(
        **{
            **vars(authorization),
            "snapshot_digest": None,
        }
    )
    check(
        snapshot,
        missing_digest,
        "invalid_start_snapshot_digest",
    )

def make_integrity_authorization(snapshot):
    """Build a valid Start authorization for dispatch-gate tests."""
    from types import SimpleNamespace
    from app.assessment_start import SNAPSHOT_VERSION
    from app.baseline_catalog import fingerprint

    snapshot["schema_version"] = SNAPSHOT_VERSION
    snapshot["assessment_id"] = "assessment-1"
    snapshot["lifecycle_status"] = "Draft"
    snapshot["mode"] = "full"

    return SimpleNamespace(
        assessment_id="assessment-1",
        snapshot_version=SNAPSHOT_VERSION,
        mode="full",
        snapshot_digest=fingerprint(snapshot),
        snapshot=snapshot,
    )




def test_dispatch_system_authorization_scenarios(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from app import nmap_dispatch_authorization as module
    from app import system_authorization_verifier

    db = MagicMock()

    snapshot_policy = {
        "digest": "policy-digest",
        "approval_reference": "system-auth-ref",
    }

    policy = SimpleNamespace(
        approval={
            "reference": "system-auth-ref",
            "digest": "policy-digest",
        }
    )

    def fake_verify(db, reference, digest):
        assert reference == "system-auth-ref"
        assert digest == "policy-digest"
        return {
            "valid": True,
            "reason": "authorization_valid",
        }

    monkeypatch.setattr(
        system_authorization_verifier,
        "verify_system_authorization",
        fake_verify,
    )

    result = module.verify_dispatch_system_authorization(
        db, snapshot_policy, policy
    )
    assert result.authorized is False
    assert (
        result.reason_code
        == "system_authorization_verified_dispatch_pending"
    )

    missing = {
        "digest": "policy-digest",
        "approval_reference": None,
    }
    result = module.verify_dispatch_system_authorization(
        db, missing, policy
    )
    assert result.reason_code == "missing_start_system_authorization"

    mismatched = {
        "digest": "policy-digest",
        "approval_reference": "different-ref",
    }
    result = module.verify_dispatch_system_authorization(
        db, mismatched, policy
    )
    assert (
        result.reason_code
        == "start_system_authorization_reference_mismatch"
    )

    wrong_digest = SimpleNamespace(
        approval={
            "reference": "system-auth-ref",
            "digest": "different-digest",
        }
    )
    result = module.verify_dispatch_system_authorization(
        db, snapshot_policy, wrong_digest
    )
    assert (
        result.reason_code
        == "start_system_authorization_policy_mismatch"
    )

    def invalid_verify(db, reference, digest):
        return {
            "valid": False,
            "reason": "authorization_revoked",
        }

    monkeypatch.setattr(
        system_authorization_verifier,
        "verify_system_authorization",
        invalid_verify,
    )

    result = module.verify_dispatch_system_authorization(
        db, snapshot_policy, policy
    )
    assert result.authorized is False
    assert result.reason_code == "start_system_authorization_invalid"
