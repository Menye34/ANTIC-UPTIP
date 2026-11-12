"""Tests for system-managed authorization preparation."""

from datetime import datetime, timezone

import pytest

from app.system_authorization_issuer import prepare_system_authorization
from app.system_authorization_signing import verify_authorization_signature
from app.system_policy_integrity import trusted_policy_digest


def test_issuer_creates_valid_signed_record(monkeypatch):
    monkeypatch.setenv(
        "UPTIP_SYSTEM_AUTH_SIGNING_KEY",
        "test-only-key-" + "a" * 48,
    )

    record = prepare_system_authorization(validity_minutes=30)

    assert record["policy_digest"] == trusted_policy_digest()
    assert record["reference"].startswith("system-auth-")
    assert record["valid_until"] > record["valid_from"]

    assert verify_authorization_signature(
        record["provenance"],
        record["reference"],
        record["policy_digest"],
        record["valid_from"].isoformat(),
        record["valid_until"].isoformat(),
    )


@pytest.mark.parametrize("minutes", [0, -1, 61, True, 1.5])
def test_invalid_validity_rejected(minutes):
    with pytest.raises(ValueError):
        prepare_system_authorization(validity_minutes=minutes)


def test_missing_signing_key_rejected(monkeypatch):
    monkeypatch.delenv("UPTIP_SYSTEM_AUTH_SIGNING_KEY", raising=False)

    with pytest.raises(RuntimeError):
        prepare_system_authorization()


def test_naive_timestamp_rejected(monkeypatch):
    monkeypatch.setenv(
        "UPTIP_SYSTEM_AUTH_SIGNING_KEY",
        "test-only-key-" + "a" * 48,
    )

    with pytest.raises(ValueError):
        prepare_system_authorization(
            now=datetime(2026, 11, 11, 12, 0),
        )
