"""Conservative classification of normalized Nikto observations."""

import re

RULE_VERSION = "nikto-findings-v1"

HEADER_RULES = {
    "content-security-policy": {
        "title": "Content Security Policy (CSP) Header Not Set",
        "severity": "Medium",
        "impact": (
            "Missing CSP may reduce browser-side protection "
            "against script injection and unauthorized content."
        ),
        "remediation": (
            "Configure an appropriate Content-Security-Policy "
            "header based on application requirements."
        ),
    },
    "x-content-type-options": {
        "title": "X-Content-Type-Options Header Not Set",
        "severity": "Low",
        "impact": (
            "Browsers may interpret resources using unintended "
            "content types."
        ),
        "remediation": (
            "Set X-Content-Type-Options to nosniff and "
            "ensure correct response content types."
        ),
    },
    "referrer-policy": {
        "title": "Referrer-Policy Header Not Set",
        "severity": "Low",
        "impact": (
            "Referrer information may be disclosed beyond "
            "the application's intended policy."
        ),
        "remediation": (
            "Configure a Referrer-Policy appropriate "
            "to the application's privacy requirements."
        ),
    },
    "strict-transport-security": {
        "title": "HTTP Strict Transport Security Header Not Set",
        "severity": "Low",
        "impact": (
            "Browsers may lack explicit instructions "
            "to enforce HTTPS for subsequent connections."
        ),
        "remediation": (
            "Configure Strict-Transport-Security after "
            "confirming reliable HTTPS support."
        ),
    },
    "permissions-policy": {
        "title": "Permissions-Policy Header Not Set",
        "severity": "Low",
        "impact": (
            "Browser features may not be restricted "
            "according to application requirements."
        ),
        "remediation": (
            "Configure Permissions-Policy to restrict "
            "unnecessary browser features."
        ),
    },
}


def classify(observation_type, data, is_partial=False):
    """Return a candidate finding or None.

    Classification does not confirm exploitability.
    """
    if is_partial or observation_type != "http_server_test":
        return None

    if not isinstance(data, dict):
        return None

    if data.get("tool") != "Nikto":
        return None

    message = data.get("message")
    scheme = data.get("scheme")

    if not isinstance(message, str):
        return None

    if scheme not in ("http", "https"):
        return None

    for header, rule in HEADER_RULES.items():
        escaped = re.escape(header)

        patterns = (
            rf"^Suggested security header missing:\s*"
            rf"{escaped}(?=[.\s]|$)",
            rf"^(?:The\s+)?{escaped}\s+header\s+"
            rf"(?:is\s+)?(?:not set|not defined|missing)\b",
        )

        if not any(
            re.search(pattern, message, re.IGNORECASE)
            for pattern in patterns
        ):
            continue

        if header == "strict-transport-security":
            if scheme != "https":
                return None

        return {
            **rule,
            "issue_key": f"missing-header:{header}",
            "security_control": header,
            "description": (
                f"Nikto reported that the {header} "
                "response header was missing. "
                "The observation requires analyst review."
            ),
            "observed_condition": message,
            "detected_issue": f"{header} header missing",
        }

    return None
