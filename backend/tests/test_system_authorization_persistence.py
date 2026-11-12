"""Tests for controlled system authorization persistence."""

from unittest.mock import MagicMock, patch

import pytest

from app.system_authorization_persistence import (
    create_system_authorization,
)
from app.system_policy_catalog import configured_policy
from app.system_policy_integrity import trusted_policy_digest


def test_missing_policy_rejected():
    db = MagicMock()
    db.execute.return_value.scalars.return_value.all.return_value = []

    with pytest.raises(RuntimeError, match="Exactly one trusted"):
        create_system_authorization(db)

    db.add.assert_not_called()


def test_duplicate_policy_rejected():
    db = MagicMock()
    db.execute.return_value.scalars.return_value.all.return_value = [
        MagicMock(),
        MagicMock(),
    ]

    with pytest.raises(RuntimeError, match="Exactly one trusted"):
        create_system_authorization(db)

    db.add.assert_not_called()


def test_tampered_policy_rejected():
    db = MagicMock()

    definition = configured_policy().model_dump(mode="json")
    definition["rules"][0]["max_units"] = 999

    policy = MagicMock()
    policy.definition = definition

    db.execute.return_value.scalars.return_value.all.return_value = [
        policy
    ]

    with pytest.raises(RuntimeError, match="Policy integrity failed"):
        create_system_authorization(db)

    db.add.assert_not_called()


def test_valid_authorization_staged(monkeypatch):
    monkeypatch.setenv(
        "UPTIP_SYSTEM_AUTH_SIGNING_KEY",
        "test-only-key-" + "a" * 48,
    )

    db = MagicMock()

    policy = MagicMock()
    policy.definition = configured_policy().model_dump(mode="json")

    db.execute.return_value.scalars.return_value.all.return_value = [
        policy
    ]

    record = create_system_authorization(
        db,
        validity_minutes=30,
    )

    assert record.policy_digest == trusted_policy_digest()
    assert record.reference.startswith("system-auth-")

    db.add.assert_called_once_with(record)
    db.flush.assert_called_once()
    db.commit.assert_not_called()
