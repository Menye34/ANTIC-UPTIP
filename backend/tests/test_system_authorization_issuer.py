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


@pytest.mark.parametrize('microsecond', [0, 123456])
def test_timestamp_offsets_preserve_original_utc_signatures(monkeypatch, microsecond):
    """Reproduce the old payload independently; no permissive fallback."""
    import hashlib
    import hmac
    import json
    from datetime import timedelta
    from app.system_authorization_signing import sign_authorization

    key = 'synthetic-timezone-regression-key-' + 'x' * 32
    monkeypatch.setenv('UPTIP_SYSTEM_AUTH_SIGNING_KEY', key)
    start = datetime(2026, 11, 13, 12, 0, microsecond=microsecond, tzinfo=timezone.utc)
    end = start + timedelta(minutes=30)
    fields = dict(reference='legacy-utc-record', policy_digest='a' * 64,
                  valid_from=start.isoformat(), valid_until=end.isoformat())
    legacy_payload = json.dumps(fields, sort_keys=True, separators=(',', ':')).encode('utf-8')
    legacy_signature = hmac.new(key.encode(), legacy_payload, hashlib.sha256).hexdigest()
    assert sign_authorization(**fields) == legacy_signature
    for offset in (1, -5, 5.5):
        zone = timezone(timedelta(hours=offset))
        shifted = {**fields, 'valid_from': start.astimezone(zone).isoformat(),
                   'valid_until': end.astimezone(zone).isoformat()}
        assert sign_authorization(**shifted) == legacy_signature
        assert verify_authorization_signature(legacy_signature, **shifted)


@pytest.mark.parametrize('field,value', [
    ('reference', 'other-record'), ('policy_digest', 'b' * 64),
    ('valid_from', '2026-11-13T12:00:01+00:00'),
    ('valid_until', '2026-11-13T12:31:00+00:00'),
])
def test_changed_signed_field_is_rejected(monkeypatch, field, value):
    from app.system_authorization_signing import sign_authorization
    monkeypatch.setenv('UPTIP_SYSTEM_AUTH_SIGNING_KEY', 'synthetic-timestamp-key-' + 'x' * 48)
    fields = dict(reference='original-record', policy_digest='a' * 64,
                  valid_from='2026-11-13T12:00:00+00:00', valid_until='2026-11-13T12:30:00+00:00')
    signature = sign_authorization(**fields)
    assert not verify_authorization_signature(signature, **{**fields, field: value})
    assert not verify_authorization_signature('0' * 64, **fields)


@pytest.mark.parametrize('invalid', ['2026-11-13T12:00:00', 'not-a-date', None])
def test_untrusted_timestamp_representation_fails_closed(monkeypatch, invalid):
    monkeypatch.setenv('UPTIP_SYSTEM_AUTH_SIGNING_KEY', 'synthetic-timestamp-key-' + 'x' * 48)
    assert not verify_authorization_signature('0' * 64, 'reference', 'a' * 64,
                                              invalid, '2026-11-13T12:30:00+00:00')
