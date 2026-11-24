"""Unit contracts for finding AI context preparation."""

from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from app import finding_ai_context as context


@pytest.fixture
def finding():
    values = {
        field: "Example " + field
        for field in context.FINDING_FIELDS
    }
    values.update(
        id=uuid4(),
        assessment_id=uuid4(),
        identity_key="a" * 64,
        title="Content Security Policy Header Not Set",
        severity="Medium",
        affected_target="https://example.test",
        source="Nikto",
    )
    return SimpleNamespace(**values)


@pytest.fixture
def setup_context(monkeypatch, finding):
    db = Mock()
    db.scalar.return_value = finding

    monkeypatch.setattr(
        context, "accessible", lambda user: True
    )

    baseline = Mock(return_value=[])
    nikto = Mock(return_value=[])

    monkeypatch.setattr(
        context, "baseline_candidates", baseline
    )
    monkeypatch.setattr(
        context, "nikto_candidates", nikto
    )

    user = SimpleNamespace(id=uuid4())

    return db, user, baseline, nikto


def fields(finding):
    return {
        "title": finding.title,
        "severity": finding.severity,
        "affected_target": finding.affected_target,
        "observed_condition": "Header absent",
    }


def nikto_record(finding, key=None):
    observation = SimpleNamespace(
        id=uuid4(),
        job_id=uuid4(),
        observation_type="http_server_test",
        data={"message": "CSP header missing"},
    )

    return (
        observation,
        key if key is not None else finding.identity_key,
        fields(finding),
    )


def retrieve(finding, setup_context):
    db, user, _, _ = setup_context

    return context.retrieve_context(
        db,
        finding.assessment_id,
        finding.id,
        user,
    )


def test_bounded_text_preserves_normal_text():
    assert context.bounded_text("Header absent") == "Header absent"


def test_bounded_text_rejects_non_text():
    for value in (None, 42, {}, []):
        assert context.bounded_text(value) == ""


def test_bounded_text_removes_control_characters():
    assert context.bounded_text("A\x00B\x1bC") == "ABC"


def test_bounded_text_truncates_long_content():
    result = context.bounded_text("a" * 1000, 100)
    assert result == "a" * 100 + " [truncated]"


def test_finding_identity_matching(finding):
    assert context.matches_finding(
        finding, finding.identity_key, fields(finding)
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("title", "Different finding"),
        ("severity", "Critical"),
        ("affected_target", "https://other.test"),
    ],
)
def test_mismatched_fields_rejected(finding, field, value):
    data = fields(finding)
    data[field] = value

    assert not context.matches_finding(
        finding, finding.identity_key, data
    )


def test_mismatched_identity_rejected(finding):
    assert not context.matches_finding(
        finding, "b" * 64, fields(finding)
    )


def test_missing_finding_stops_retrieval(
    finding, setup_context
):
    db, user, baseline, nikto = setup_context
    db.scalar.return_value = None

    with pytest.raises(HTTPException) as error:
        retrieve(finding, setup_context)

    assert error.value.status_code == 404
    baseline.assert_not_called()
    nikto.assert_not_called()


def test_missing_evidence_state(finding, setup_context):
    result = retrieve(finding, setup_context)

    assert result["finding_id"] == str(finding.id)
    assert result["evidence"] == []
    assert result["evidence_available"] is False
    assert result["eligible_evidence_count"] == 0
    assert result["original_output_included"] is False

    assert any(
        "No eligible linked" in item
        for item in result["limitations"]
    )


def test_candidate_queries_are_finding_scoped(
    finding, setup_context
):
    db, _, baseline, nikto = setup_context

    retrieve(finding, setup_context)

    for candidate in (baseline, nikto):
        candidate.assert_called_once_with(
            db,
            finding.assessment_id,
            finding_id=finding.id,
        )


def test_nikto_evidence_retrieval(finding, setup_context):
    _, _, _, nikto = setup_context
    record = nikto_record(finding)
    nikto.return_value = [record]

    result = retrieve(finding, setup_context)

    assert result["evidence_available"] is True
    assert result["evidence_included_count"] == 1

    evidence = result["evidence"][0]

    assert evidence["observation_id"] == str(record[0].id)
    assert evidence["source"] == "Nikto"
    assert evidence["content"] == "CSP header missing"
    assert evidence["exploitation_confirmed"] is False


def test_baseline_evidence_retrieval(
    finding, setup_context
):
    _, _, baseline, _ = setup_context

    observation = SimpleNamespace(
        id=uuid4(),
        observation_type="security_issue",
    )

    original = SimpleNamespace(
        id=uuid4(),
        tool="Example scanner",
    )

    baseline.return_value = [
        (
            observation,
            original,
            None,
            finding.identity_key,
            fields(finding),
        )
    ]

    result = retrieve(finding, setup_context)
    evidence = result["evidence"][0]

    assert evidence["observation_id"] == str(observation.id)
    assert evidence["evidence_id"] == str(original.id)
    assert evidence["content"] == "Header absent"
    assert evidence["exploitation_confirmed"] is False


def test_mismatched_evidence_excluded(
    finding, setup_context
):
    _, _, _, nikto = setup_context

    nikto.return_value = [
        nikto_record(finding, key="b" * 64)
    ]

    result = retrieve(finding, setup_context)

    assert result["evidence_available"] is False
    assert result["eligible_evidence_count"] == 0


def test_evidence_quantity_limit(finding, setup_context):
    _, _, _, nikto = setup_context

    nikto.return_value = [
        nikto_record(finding)
        for _ in range(5)
    ]

    result = retrieve(finding, setup_context)

    assert result["eligible_evidence_count"] == 5
    assert result["evidence_included_count"] == 3
    assert len(result["evidence"]) == 3

    assert any(
        "omitted" in item
        for item in result["limitations"]
    )


def test_evidence_content_limit(finding, setup_context):
    _, _, _, nikto = setup_context

    record = nikto_record(finding)
    record[0].data["message"] = "x" * 2000
    nikto.return_value = [record]

    result = retrieve(finding, setup_context)

    assert result["evidence"][0]["content"] == (
        "x" * context.MAX_EVIDENCE_LENGTH
        + " [truncated]"
    )


def test_context_does_not_write_records(
    finding, setup_context
):
    db, _, _, _ = setup_context

    retrieve(finding, setup_context)

    for operation in (
        "add", "add_all", "delete", "flush", "commit"
    ):
        getattr(db, operation).assert_not_called()
