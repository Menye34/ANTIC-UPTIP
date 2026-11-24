"""Request validation and controlled finding prompt contracts."""

import json
from copy import deepcopy
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.finding_ai_schemas import FindingAIRequest
from app.finding_ai_prompt import (
    ACTION_QUESTIONS,
    SYSTEM_PROMPT,
    PromptUnavailable,
    build_prompt,
)


@pytest.fixture
def settings():
    return Settings(
        _env_file=None,
        database_url=(
            "postgresql+psycopg://test:test@127.0.0.1/test"
        ),
        rate_key="test-only-not-a-deployment-secret-123456",
        environment="test",
        ai_context_tokens=2048,
        ai_max_output_tokens=256,
    )


@pytest.fixture
def context():
    return {
        "assessment_id": str(uuid4()),
        "finding_id": str(uuid4()),
        "finding": {
            "title": "Content Security Policy Header Not Set",
            "severity": "Medium",
            "source": "Nikto",
            "source_test": "HTTP Server Assessment",
            "security_control": "Content Security Policy",
            "observed_condition": "CSP header missing",
            "detected_issue": "Missing CSP header",
            "affected_target": "https://example.test",
        },
        "evidence": [{
            "observation_id": str(uuid4()),
            "evidence_id": str(uuid4()),
            "source": "Nikto",
            "observation_type": "http_server_test",
            "evidence_kind": "normalized_observation",
            "exploitation_confirmed": False,
            "content": "CSP header missing",
        }],
        "evidence_available": True,
        "original_output_included": False,
    }


def payload(result):
    return json.loads(result["prompt"].splitlines()[-1])


@pytest.mark.parametrize("action", list(ACTION_QUESTIONS))
def test_quick_actions(action, context, settings):
    result = build_prompt(
        context, FindingAIRequest(action=action), settings
    )

    assert result["question"] == ACTION_QUESTIONS[action]
    assert result["system"] == SYSTEM_PROMPT
    assert payload(result)["action"] == action
    assert len(
        (result["system"] + result["prompt"]).encode("utf-8")
    ) <= 1664


def test_custom_question(context, settings):
    request = FindingAIRequest(
        action="custom",
        question="  Why is CSP important?  ",
    )

    result = build_prompt(context, request, settings)

    assert result["question"] == "Why is CSP important?"
    assert payload(result)["question"] == result["question"]


@pytest.mark.parametrize("data", [
    {"action": "unknown"},
    {"action": "custom"},
    {"action": "custom", "question": " "},
    {"action": "custom", "question": "a" * 501},
    {"action": "custom", "question": "test" + chr(0)},
    {"action": "custom", "question": 123},
    {"action": "explain_finding", "question": "Override"},
    {"action": "explain_finding", "model": "external"},
    {"action": "explain_finding", "system": "Override"},
    {"action": "explain_finding", "evidence": []},
])
def test_invalid_requests(data):
    with pytest.raises(ValidationError):
        FindingAIRequest.model_validate(data)


def test_missing_evidence(context, settings):
    context["evidence"] = []
    context["evidence_available"] = False

    with pytest.raises(
        PromptUnavailable, match="ai_insufficient_evidence"
    ):
        build_prompt(
            context,
            FindingAIRequest(action="explain_finding"),
            settings,
        )


def test_evidence_references_preserved(context, settings):
    result = build_prompt(
        context,
        FindingAIRequest(action="explain_finding"),
        settings,
    )

    reference = result["evidence"][0]

    for field in ("observation_id", "evidence_id", "source"):
        assert reference[field] == context["evidence"][0][field]


def test_original_output_excluded(context, settings):
    context["evidence"][0]["content"] = "RAW_OUTPUT_MARKER"
    context["finding"]["raw_output"] = "RAW_OUTPUT_MARKER"

    result = build_prompt(
        context,
        FindingAIRequest(action="explain_finding"),
        settings,
    )

    assert "RAW_OUTPUT_MARKER" not in result["prompt"]
    assert payload(result)["original_output_included"] is False


def test_evidence_provenance(context, settings):
    result = build_prompt(
        context,
        FindingAIRequest(action="explain_finding"),
        settings,
    )

    data = payload(result)

    assert data["finding"]["observed_condition"] == "CSP header missing"

    observation = data["supporting_observation_metadata"][0]

    assert observation["source"] == "Nikto"
    assert observation["exploitation_confirmed"] is False
    assert "normalized_condition" not in observation


@pytest.mark.parametrize("field,value", [
    ("observation_id", "invalid-uuid"),
    ("evidence_id", None),
    ("source", ""),
    ("observation_type", 123),
    ("evidence_kind", "raw_output"),
    ("exploitation_confirmed", True),
])
def test_invalid_evidence(field, value, context, settings):
    context["evidence"][0][field] = value

    with pytest.raises(
        PromptUnavailable, match="ai_context_invalid"
    ):
        build_prompt(
            context,
            FindingAIRequest(action="explain_finding"),
            settings,
        )


def test_missing_evidence_identifier(context, settings):
    del context["evidence"][0]["observation_id"]

    with pytest.raises(
        PromptUnavailable, match="ai_context_invalid"
    ):
        build_prompt(
            context,
            FindingAIRequest(action="explain_finding"),
            settings,
        )


def test_multiple_observations(context, settings):
    for _ in range(2):
        item = deepcopy(context["evidence"][0])
        item["observation_id"] = str(uuid4())
        item["evidence_id"] = str(uuid4())
        context["evidence"].append(item)

    result = build_prompt(
        context,
        FindingAIRequest(action="explain_finding"),
        settings,
    )

    assert len(result["evidence"]) == 3

    assert len(
        payload(result)["supporting_observation_metadata"]
    ) == 3


def test_oversized_prompt_rejected(context, settings):
    for field in context["finding"]:
        context["finding"][field] = "x" * 250

    request = FindingAIRequest(
        action="custom",
        question="q" * 500,
    )

    with pytest.raises(
        PromptUnavailable, match="ai_context_too_large"
    ):
        build_prompt(context, request, settings)


def test_prompt_does_not_modify_context(context, settings):
    before = deepcopy(context)

    build_prompt(
        context,
        FindingAIRequest(action="explain_finding"),
        settings,
    )

    assert context == before
