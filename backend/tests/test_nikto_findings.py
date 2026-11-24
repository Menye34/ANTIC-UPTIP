import pytest

from app.nikto_findings import classify


def observation(message, scheme="http"):
    return {
        "tool": "Nikto",
        "address": "192.0.2.10",
        "port": 8080,
        "scheme": scheme,
        "path": "/",
        "message": message,
        "verification": "unverified",
    }


@pytest.mark.parametrize("header,severity", [
    ("content-security-policy", "Medium"),
    ("x-content-type-options", "Low"),
    ("referrer-policy", "Low"),
    ("permissions-policy", "Low"),
])
def test_missing_headers(header, severity):
    result = classify(
        "http_server_test",
        observation(f"Suggested security header missing: {header}.")
    )

    assert result is not None
    assert result["severity"] == severity
    assert result["issue_key"] == f"missing-header:{header}"


def test_duplicate_header_identity():
    first = classify(
        "http_server_test",
        observation("The X-Content-Type-Options header is not set.")
    )
    second = classify(
        "http_server_test",
        observation(
            "Suggested security header missing: x-content-type-options."
        )
    )

    assert first is not None
    assert second is not None
    assert first["issue_key"] == second["issue_key"]


@pytest.mark.parametrize("scheme,expected", [
    ("http", False),
    ("https", True),
])
def test_hsts_applicability(scheme, expected):
    result = classify(
        "http_server_test",
        observation(
            "Suggested security header missing: strict-transport-security.",
            scheme=scheme
        )
    )

    assert (result is not None) == expected


@pytest.mark.parametrize("message", [
    "CGI directory found.",
    "Directory indexing appears to be enabled.",
    "X-Frame-Options header is deprecated.",
    "Server information detected.",
    "Unknown scanner observation.",
])
def test_informational_observations(message):
    assert classify(
        "http_server_test",
        observation(message)
    ) is None


def test_partial_observation_excluded():
    assert classify(
        "http_server_test",
        observation(
            "Suggested security header missing: content-security-policy."
        ),
        is_partial=True
    ) is None


def test_discovery_observation_excluded():
    assert classify(
        "service_discovery",
        observation(
            "Suggested security header missing: content-security-policy."
        )
    ) is None


def test_other_tool_excluded():
    data = observation(
        "Suggested security header missing: content-security-policy."
    )
    data["tool"] = "Nmap"

    assert classify("http_server_test", data) is None
