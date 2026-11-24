from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.nikto_findings_processing import (
    normalize_candidate,
    matches_authorized_endpoint,
)


ASSESSMENT = uuid4()
TARGET = uuid4()

PLAN = {
    "target": "192.0.2.10",
    "port": 8080,
    "scheme": "http",
}


def observation(message=None, **overrides):
    data = {
        "tool": "Nikto",
        "address": "192.0.2.10",
        "port": 8080,
        "scheme": "http",
        "path": "/",
        "message": message or (
            "Suggested security header missing: "
            "x-content-type-options."
        ),
    }

    data.update(overrides)

    return SimpleNamespace(
        assessment_id=ASSESSMENT,
        target_id=TARGET,
        observation_type="http_server_test",
        is_partial=False,
        data=data,
    )


def test_authorized_endpoint():
    assert matches_authorized_endpoint(observation(), PLAN)


@pytest.mark.parametrize("overrides", [
    {"address": "192.0.2.20"},
    {"port": 443},
    {"scheme": "https"},
    {"port": True},
    {"address": "invalid"},
])
def test_mismatched_endpoint(overrides):
    assert not matches_authorized_endpoint(
        observation(**overrides), PLAN
    )


@pytest.mark.parametrize("plan", [
    None,
    {},
    {"target": "192.0.2.10", "port": True, "scheme": "http"},
])
def test_invalid_plan(plan):
    assert not matches_authorized_endpoint(
        observation(), plan
    )


def test_duplicate_header_identity():
    first = observation()

    second = observation(
        "The X-Content-Type-Options header is not set."
    )

    assert normalize_candidate(first)[0] == \
        normalize_candidate(second)[0]


def test_different_paths_remain_separate():
    first = observation(path="/")
    second = observation(path="/admin")

    assert normalize_candidate(first)[0] != \
        normalize_candidate(second)[0]


def test_different_ports_remain_separate():
    first = observation(port=8080)
    second = observation(port=9090)

    assert normalize_candidate(first)[0] != \
        normalize_candidate(second)[0]


def test_assessment_isolation():
    first = observation()
    second = observation()
    second.assessment_id = uuid4()

    assert normalize_candidate(first)[0] != \
        normalize_candidate(second)[0]


def test_target_isolation():
    first = observation()
    second = observation()
    second.target_id = uuid4()

    assert normalize_candidate(first)[0] != \
        normalize_candidate(second)[0]


def test_partial_observation_excluded():
    item = observation()
    item.is_partial = True

    assert normalize_candidate(item) is None


def test_informational_observation_excluded():
    item = observation("Server information detected.")

    assert normalize_candidate(item) is None


def test_affected_endpoint():
    _, fields = normalize_candidate(observation())

    assert fields["affected_target"] == \
        "http://192.0.2.10:8080/"

    assert fields["severity"] == "Low"
