"""HTTP contracts for authenticated finding AI assistance."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock, AsyncMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import routes as auth
from app import finding_ai_routes as ai
from app.config import Settings
from app.database import get_db
from app.main import create_app
from app.models import AuthSession, User
from app.security import digest, session_csrf
from app.ollama_client import OllamaUnavailable


@pytest.fixture
def setup(monkeypatch):
    settings = Settings(
        _env_file=None,
        database_url=(
            "postgresql+psycopg://test:test@127.0.0.1/test"
        ),
        rate_key="test-only-not-a-deployment-secret-123456",
        environment="test",
        public_origin="https://testserver",
        cookie_secure=True,
        ai_enabled=True,
        ai_model="qwen2.5:3b",
        ai_context_tokens=2048,
        ai_max_output_tokens=256,
    )

    from app import main

    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(auth, "get_settings", lambda: settings)
    monkeypatch.setattr(ai, "get_settings", lambda: settings)

    user = SimpleNamespace(
        id=uuid4(),
        role="Security Analyst",
    )

    session = SimpleNamespace(
        user_id=user.id,
        expires_at=datetime.now(timezone.utc)
        + timedelta(minutes=30),
    )

    token = "synthetic-ai-test-session"
    state = SimpleNamespace(
        user=user,
        session=session,
        active=True,
    )

    def lookup(model, key):
        if model is AuthSession and key == digest(token):
            return state.session
        if model is User and key == user.id:
            return state.user
        return None

    db = Mock()
    db.get.side_effect = lookup

    monkeypatch.setattr(
        auth, "can_activate", lambda principal: state.active
    )

    assessment_id = uuid4()
    finding_id = uuid4()

    context = {
        "assessment_id": str(assessment_id),
        "finding_id": str(finding_id),
        "finding": {
            "title": "Missing CSP Header",
            "severity": "Medium",
            "source": "Nikto",
            "source_test": "HTTP Server Assessment",
            "security_control": "CSP",
            "observed_condition": "CSP header missing",
            "detected_issue": "Missing CSP header",
        },
        "evidence_available": True,
        "evidence": [{
            "observation_id": str(uuid4()),
            "evidence_id": str(uuid4()),
            "source": "Nikto",
            "observation_type": "http_server_test",
            "evidence_kind": "normalized_observation",
            "exploitation_confirmed": False,
        }],
    }

    retrieve = Mock(return_value=context)

    generate = AsyncMock(return_value={
        "answer": "Configure an appropriate CSP header.",
        "model": settings.ai_model,
        "output_tokens": 12,
    })

    monkeypatch.setattr(ai, "retrieve_context", retrieve)
    monkeypatch.setattr(ai, "generate", generate)

    history_id = uuid4()
    save = Mock(return_value=history_id)
    monkeypatch.setattr(ai, "save_interaction", save)

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db

    endpoint = (
        f"/api/v1/assessments/{assessment_id}"
        f"/findings/{finding_id}/ai/ask"
    )

    with TestClient(
        app, base_url="https://testserver"
    ) as client:
        client.cookies.set(settings.cookie_name, token)
        client.headers.update({
            "Origin": settings.public_origin,
            "X-CSRF-Token": session_csrf(settings, token),
        })

        yield SimpleNamespace(
            client=client,
            endpoint=endpoint,
            settings=settings,
            state=state,
            db=db,
            context=context,
            retrieve=retrieve,
            generate=generate,
            save=save,
            history_id=history_id,
            assessment_id=assessment_id,
            finding_id=finding_id,
        )

    app.dependency_overrides.clear()


def ask(setup, body=None, **kwargs):
    return setup.client.post(
        setup.endpoint,
        json=body if body is not None else {
            "action": "explain_finding"
        },
        **kwargs,
    )


def assert_no_inference(setup):
    setup.generate.assert_not_awaited()
    setup.save.assert_not_called()


def test_authenticated_answer(setup):
    response = ask(setup)

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "answered"
    assert data["history_id"] == str(setup.history_id)
    setup.save.assert_called_once()
    assert data["assessment_id"] == str(setup.assessment_id)
    assert data["finding_id"] == str(setup.finding_id)
    assert data["advisory_only"] is True
    assert data["model"] == setup.settings.ai_model
    assert data["output_tokens"] == 12
    assert data["answer"] == "Configure an appropriate CSP header."
    assert len(data["evidence"]) == 1

    reference = data["evidence"][0]
    original = setup.context["evidence"][0]

    assert reference["observation_id"] == original["observation_id"]
    assert reference["evidence_id"] == original["evidence_id"]

    assert response.headers["cache-control"] == "no-store"

    setup.generate.assert_awaited_once()
    assert setup.retrieve.call_count == 2
    setup.db.rollback.assert_called_once()

    for call in setup.retrieve.call_args_list:
        assert call.args[1] == setup.assessment_id
        assert call.args[2] == setup.finding_id
        assert call.args[3].id == setup.state.user.id


def test_custom_question(setup):
    response = ask(setup, {
        "action": "custom",
        "question": "Why is CSP important?",
    })

    assert response.status_code == 200
    assert response.json()["status"] == "answered"
    assert response.json()["question"] == "Why is CSP important?"


def test_missing_session(setup):
    setup.client.cookies.clear()

    assert ask(setup).status_code == 401
    setup.retrieve.assert_not_called()
    assert_no_inference(setup)


def test_expired_session(setup):
    setup.state.session.expires_at = (
        datetime.now(timezone.utc) - timedelta(seconds=1)
    )

    assert ask(setup).status_code == 401
    assert_no_inference(setup)


def test_inactive_account(setup):
    setup.state.active = False

    assert ask(setup).status_code == 401
    assert_no_inference(setup)


@pytest.mark.parametrize("role", [
    "Technical Administrator",
    "Security Administrator",
])
def test_wrong_role(setup, role):
    setup.state.user.role = role

    assert ask(setup).status_code == 403
    setup.retrieve.assert_not_called()
    assert_no_inference(setup)


@pytest.mark.parametrize("header,value", [
    ("Origin", "https://untrusted.test"),
    ("X-CSRF-Token", "invalid-token"),
])
def test_invalid_security_headers(setup, header, value):
    response = ask(setup, headers={header: value})

    assert response.status_code == 403
    setup.retrieve.assert_not_called()
    assert_no_inference(setup)


@pytest.mark.parametrize("header", [
    "Origin",
    "X-CSRF-Token",
])
def test_missing_security_headers(setup, header):
    del setup.client.headers[header]

    assert ask(setup).status_code == 403
    setup.retrieve.assert_not_called()
    assert_no_inference(setup)


@pytest.mark.parametrize("body", [
    {},
    {"action": "invalid"},
    {"action": "custom"},
    {"action": "custom", "question": "q" * 501},
    {"action": "explain_finding", "model": "other-model"},
])
def test_invalid_request(setup, body):
    assert ask(setup, body).status_code == 422
    assert_no_inference(setup)


def test_unauthorized_finding(setup):
    setup.retrieve.side_effect = HTTPException(404)

    assert ask(setup).status_code == 404
    assert_no_inference(setup)


def test_disabled_ai_still_checks_authorization(setup):
    setup.settings.ai_enabled = False
    setup.retrieve.side_effect = HTTPException(404)

    assert ask(setup).status_code == 404
    assert_no_inference(setup)


def test_ai_disabled(setup):
    setup.settings.ai_enabled = False

    response = ask(setup)

    assert response.status_code == 200
    assert response.json()["status"] == "unavailable"
    assert response.json()["code"] == "ai_disabled"
    assert_no_inference(setup)


def test_insufficient_evidence(setup):
    setup.context["evidence"] = []
    setup.context["evidence_available"] = False

    response = ask(setup)

    assert response.status_code == 200
    assert response.json()["status"] == "insufficient_evidence"
    assert_no_inference(setup)


def test_invalid_evidence(setup):
    setup.context["evidence"][0]["evidence_id"] = "invalid"

    response = ask(setup)

    assert response.status_code == 200
    assert response.json()["code"] == "ai_context_invalid"
    assert_no_inference(setup)


def test_context_too_large(setup):
    setup.context["finding"]["observed_condition"] = "x" * 250
    setup.context["finding"]["detected_issue"] = "x" * 250

    response = ask(setup, {
        "action": "custom",
        "question": "q" * 500,
    })

    assert response.status_code == 200
    assert response.json()["code"] == "ai_context_too_large"
    assert_no_inference(setup)


def test_busy_inference(setup):
    assert ai.inference_lock.acquire(blocking=False)

    try:
        response = ask(setup)

        assert response.status_code == 200
        assert response.json()["code"] == "ai_busy"
        assert response.json()["retryable"] is True
        assert_no_inference(setup)
    finally:
        ai.inference_lock.release()


@pytest.mark.parametrize("code", [
    "ai_timeout",
    "ai_service_unavailable",
    "ai_response_invalid",
    "ai_response_incomplete",
    "ai_response_empty",
    "ai_response_too_large",
    "ai_model_mismatch",
])
def test_controlled_inference_failure(setup, code):
    setup.generate.side_effect = OllamaUnavailable(code)

    response = ask(setup)

    assert response.status_code == 200
    assert response.json()["status"] == "unavailable"
    assert response.json()["code"] == code
    assert "answer" not in response.json()
    assert not ai.inference_lock.locked()


def test_internal_error_details_not_exposed(setup):
    setup.generate.side_effect = OllamaUnavailable(
        "internal-sensitive-details"
    )

    response = ask(setup)

    assert response.json()["code"] == "ai_service_unavailable"
    assert "internal-sensitive-details" not in response.text


def test_lock_released_after_failure(setup):
    setup.generate.side_effect = OllamaUnavailable("ai_timeout")

    assert ask(setup).json()["code"] == "ai_timeout"

    setup.generate.side_effect = None

    assert ask(setup).json()["status"] == "answered"
    assert not ai.inference_lock.locked()


def test_session_revoked_during_inference(setup):
    async def revoke(**kwargs):
        setup.state.session = None
        return setup.generate.return_value

    setup.generate.side_effect = revoke

    response = ask(setup)

    assert response.status_code == 401
    assert "Configure an appropriate" not in response.text
    assert not ai.inference_lock.locked()


def test_role_changed_during_inference(setup):
    async def change_role(**kwargs):
        setup.state.user.role = "Technical Administrator"
        return setup.generate.return_value

    setup.generate.side_effect = change_role

    response = ask(setup)

    assert response.status_code == 403
    assert "Configure an appropriate" not in response.text
    assert not ai.inference_lock.locked()


def test_assessment_access_revoked_during_inference(setup):
    setup.retrieve.side_effect = [
        setup.context,
        HTTPException(404),
    ]

    response = ask(setup)

    assert response.status_code == 404
    assert "Configure an appropriate" not in response.text
    assert not ai.inference_lock.locked()


def test_context_changed_during_inference(setup):
    changed = deepcopy(setup.context)
    changed["finding"]["severity"] = "High"

    setup.retrieve.side_effect = [
        setup.context,
        changed,
    ]

    response = ask(setup)

    assert response.status_code == 200
    assert response.json()["code"] == "ai_context_changed"
    assert "answer" not in response.json()
    assert not ai.inference_lock.locked()


@pytest.mark.parametrize("result", [
    {},
    {
        "answer": "",
        "model": "qwen2.5:3b",
        "output_tokens": 12,
    },
    {
        "answer": "x" * 6001,
        "model": "qwen2.5:3b",
        "output_tokens": 12,
    },
])
def test_invalid_answer_contract(setup, result):
    setup.generate.return_value = result

    response = ask(setup)

    assert response.status_code == 200
    assert response.json()["code"] == "ai_response_invalid"
    assert not ai.inference_lock.locked()


def test_read_only_operations(setup):
    before = deepcopy(setup.context)

    assert ask(setup).json()["status"] == "answered"
    assert setup.context == before

    for operation in (
        "add", "add_all", "delete", "flush", "commit"
    ):
        getattr(setup.db, operation).assert_not_called()


def test_history_save_failure(setup):
    from sqlalchemy.exc import SQLAlchemyError

    setup.save.side_effect = SQLAlchemyError(
        "sensitive-database-details"
    )

    response = ask(setup)

    assert response.status_code == 200
    assert response.json()["code"] == "ai_history_unavailable"
    assert "answer" not in response.json()
    assert "sensitive-database-details" not in response.text
    assert not ai.inference_lock.locked()
    assert setup.db.rollback.call_count == 2


def test_successful_answer_saved_with_actor(setup):
    response = ask(setup)

    assert response.json()["status"] == "answered"

    setup.save.assert_called_once()

    db, actor_id, answer, prompt_version = (
        setup.save.call_args.args
    )

    assert db is setup.db
    assert actor_id == setup.state.user.id
    assert answer.assessment_id == setup.assessment_id
    assert answer.finding_id == setup.finding_id
    assert answer.answer == response.json()["answer"]
    assert prompt_version


def test_failed_inference_not_saved(setup):
    setup.generate.side_effect = OllamaUnavailable("ai_timeout")

    assert ask(setup).json()["code"] == "ai_timeout"
    setup.save.assert_not_called()


def test_history_endpoint(setup, monkeypatch):
    from app.finding_ai_schemas import FindingAIHistoryResponse

    retrieve = Mock(return_value=FindingAIHistoryResponse(
        assessment_id=setup.assessment_id,
        finding_id=setup.finding_id,
        entries=[],
        limit=20,
        offset=0,
        has_more=False,
    ))

    monkeypatch.setattr(ai, "retrieve_history", retrieve)

    setup.settings.ai_enabled = False

    response = setup.client.get(
        setup.endpoint.removesuffix("/ask") + "/history"
    )

    assert response.status_code == 200
    assert response.json()["entries"] == []
    assert response.json()["has_more"] is False

    retrieve.assert_called_once_with(
        setup.db,
        setup.assessment_id,
        setup.finding_id,
        setup.state.user,
        limit=20,
        offset=0,
    )

    setup.generate.assert_not_awaited()


def test_history_requires_authentication(setup):
    setup.client.cookies.clear()

    response = setup.client.get(
        setup.endpoint.removesuffix("/ask") + "/history"
    )

    assert response.status_code == 401


def test_history_requires_analyst_role(setup):
    setup.state.user.role = "Technical Administrator"

    response = setup.client.get(
        setup.endpoint.removesuffix("/ask") + "/history"
    )

    assert response.status_code == 403


def test_history_invalid_pagination(setup):
    response = setup.client.get(
        setup.endpoint.removesuffix("/ask") + "/history",
        params={"limit": 51},
    )

    assert response.status_code == 422


def test_history_unauthorized_finding(setup, monkeypatch):
    retrieve = Mock(side_effect=HTTPException(404))

    monkeypatch.setattr(ai, "retrieve_history", retrieve)

    response = setup.client.get(
        setup.endpoint.removesuffix("/ask") + "/history"
    )

    assert response.status_code == 404
