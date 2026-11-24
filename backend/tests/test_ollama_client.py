"""Synthetic Ollama response tests; no real AI inference."""

import pytest

from app.config import Settings
from app.ollama_client import (
    OllamaUnavailable,
    validate_response,
    MAX_ANSWER_CHARACTERS,
)


@pytest.fixture
def ai_settings():
    return Settings(
        _env_file=None,
        database_url="postgresql+psycopg://test:test@127.0.0.1/test",
        rate_key="test-only-not-a-deployment-secret-123456",
        environment="test",
        ai_enabled=True,
        ai_model="qwen2.5:3b",
        ai_max_output_tokens=256,
    )


@pytest.fixture
def valid_response():
    return {
        "model": "qwen2.5:3b",
        "done": True,
        "done_reason": "stop",
        "response": "The missing CSP header may increase content injection risks.",
        "eval_count": 18,
        "context": [1, 2, 3],
        "total_duration": 1000000,
    }


def test_valid_response(ai_settings, valid_response):
    result = validate_response(valid_response, ai_settings)

    assert result == {
        "answer": valid_response["response"],
        "model": "qwen2.5:3b",
        "output_tokens": 18,
    }


def test_answer_whitespace(ai_settings, valid_response):
    valid_response["response"] = "  Explanation.  "

    result = validate_response(valid_response, ai_settings)

    assert result["answer"] == "Explanation."


def test_multiline_answer(ai_settings, valid_response):
    valid_response["response"] = "Explanation.\n\nSuggested remediation."

    result = validate_response(valid_response, ai_settings)

    assert result["answer"] == valid_response["response"]


@pytest.mark.parametrize(
    "changes,expected_code",
    [
        (
            {"error": "Internal service failure"},
            "ai_service_unavailable",
        ),
        (
            {"model": "unexpected-model"},
            "ai_model_mismatch",
        ),
        (
            {"done": False},
            "ai_response_incomplete",
        ),
        (
            {"done": 1},
            "ai_response_incomplete",
        ),
        (
            {"done_reason": "length"},
            "ai_response_incomplete",
        ),
        (
            {"done_reason": None},
            "ai_response_incomplete",
        ),
        (
            {"response": ""},
            "ai_response_empty",
        ),
        (
            {"response": "   "},
            "ai_response_empty",
        ),
        (
            {"response": None},
            "ai_response_empty",
        ),
        (
            {"response": 123},
            "ai_response_empty",
        ),
        (
            {"response": "x" * (MAX_ANSWER_CHARACTERS + 1)},
            "ai_response_too_large",
        ),
        (
            {"response": "Invalid\x00answer"},
            "ai_response_invalid",
        ),
        (
            {"eval_count": 0},
            "ai_response_invalid",
        ),
        (
            {"eval_count": -1},
            "ai_response_invalid",
        ),
        (
            {"eval_count": 257},
            "ai_response_invalid",
        ),
        (
            {"eval_count": True},
            "ai_response_invalid",
        ),
        (
            {"eval_count": "18"},
            "ai_response_invalid",
        ),
        (
            {"eval_count": None},
            "ai_response_invalid",
        ),
    ],
)
def test_invalid_response(
    ai_settings, valid_response, changes, expected_code
):
    response = {**valid_response, **changes}

    with pytest.raises(OllamaUnavailable) as error:
        validate_response(response, ai_settings)

    assert error.value.code == expected_code


@pytest.mark.parametrize("response", [None, [], "invalid", 123])
def test_invalid_response_structure(ai_settings, response):
    with pytest.raises(OllamaUnavailable) as error:
        validate_response(response, ai_settings)

    assert error.value.code == "ai_response_invalid"


# Complete communication tests using synthetic HTTP responses.

import asyncio
import json
import httpx

from app.ollama_client import generate, MAX_RESPONSE_BYTES


def install_mock_transport(monkeypatch, handler):
    original_client = httpx.AsyncClient
    calls = []

    def checked_handler(request):
        calls.append(request)
        assert request.url == httpx.URL(
            "http://127.0.0.1:11434/api/generate"
        )
        assert request.method == "POST"
        return handler(request)

    def mock_client(*args, **kwargs):
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False

        return original_client(
            *args,
            transport=httpx.MockTransport(checked_handler),
            **kwargs,
        )

    monkeypatch.setattr(httpx, "AsyncClient", mock_client)

    return calls


def test_generate_success(
    monkeypatch, ai_settings, valid_response
):
    def handler(request):
        payload = json.loads(request.content)

        assert payload["model"] == ai_settings.ai_model
        assert payload["system"] == "Synthetic system instruction."
        assert payload["prompt"] == "Explain the synthetic finding."
        assert payload["stream"] is False
        assert payload["keep_alive"] == ai_settings.ai_keep_alive

        options = payload["options"]

        assert options["num_ctx"] == ai_settings.ai_context_tokens
        assert options["num_predict"] == ai_settings.ai_max_output_tokens
        assert options["num_thread"] == ai_settings.ai_threads
        assert options["temperature"] == 0.2
        assert "tools" not in payload

        return httpx.Response(200, json=valid_response)

    calls = install_mock_transport(monkeypatch, handler)

    result = asyncio.run(generate(
        system="Synthetic system instruction.",
        prompt="Explain the synthetic finding.",
        settings=ai_settings,
    ))

    assert result["answer"] == valid_response["response"]
    assert result["model"] == ai_settings.ai_model
    assert result["output_tokens"] == 18
    assert len(calls) == 1


@pytest.mark.parametrize("status", [400, 404, 429, 500, 503])
def test_generate_http_failure(
    monkeypatch, ai_settings, status
):
    calls = install_mock_transport(
        monkeypatch,
        lambda request: httpx.Response(
            status,
            json={"error": "Synthetic internal failure"},
        ),
    )

    with pytest.raises(OllamaUnavailable) as error:
        asyncio.run(generate(
            system="Synthetic instruction.",
            prompt="Synthetic question.",
            settings=ai_settings,
        ))

    assert error.value.code == "ai_service_unavailable"
    assert len(calls) == 1


@pytest.mark.parametrize(
    "exception_type,expected_code",
    [
        (httpx.ConnectError, "ai_service_unavailable"),
        (httpx.ConnectTimeout, "ai_timeout"),
        (httpx.ReadTimeout, "ai_timeout"),
    ],
)
def test_generate_connection_failure(
    monkeypatch, ai_settings, exception_type, expected_code
):
    def handler(request):
        raise exception_type(
            "Synthetic connection failure",
            request=request,
        )

    calls = install_mock_transport(monkeypatch, handler)

    with pytest.raises(OllamaUnavailable) as error:
        asyncio.run(generate(
            system="Synthetic instruction.",
            prompt="Synthetic question.",
            settings=ai_settings,
        ))

    assert error.value.code == expected_code
    assert len(calls) == 1


@pytest.mark.parametrize(
    "content,expected_code",
    [
        (b"not-json", "ai_response_invalid"),
        (b"[]", "ai_response_invalid"),
        (b"", "ai_response_invalid"),
        (
            b"x" * (MAX_RESPONSE_BYTES + 1),
            "ai_response_too_large",
        ),
    ],
)
def test_generate_invalid_http_body(
    monkeypatch, ai_settings, content, expected_code
):
    calls = install_mock_transport(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            content=content,
        ),
    )

    with pytest.raises(OllamaUnavailable) as error:
        asyncio.run(generate(
            system="Synthetic instruction.",
            prompt="Synthetic question.",
            settings=ai_settings,
        ))

    assert error.value.code == expected_code
    assert len(calls) == 1


# Communication security regression tests.

from app.ollama_client import MAX_PROMPT_BYTES


def prohibit_http_client(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Unsafe request reached HTTP client")

    monkeypatch.setattr(httpx, "AsyncClient", forbidden)


def test_generate_disabled(monkeypatch, ai_settings):
    prohibit_http_client(monkeypatch)

    settings = ai_settings.model_copy(
        update={"ai_enabled": False}
    )

    with pytest.raises(OllamaUnavailable) as error:
        asyncio.run(generate(
            system="Synthetic instruction.",
            prompt="Synthetic question.",
            settings=settings,
        ))

    assert error.value.code == "ai_disabled"


@pytest.mark.parametrize("endpoint", [
    "https://example.test",
    "http://localhost:11434",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:11434/other",
])
def test_generate_unauthorized_endpoint(
    monkeypatch, ai_settings, endpoint
):
    prohibit_http_client(monkeypatch)

    settings = ai_settings.model_copy(
        update={"ai_base_url": endpoint}
    )

    with pytest.raises(OllamaUnavailable) as error:
        asyncio.run(generate(
            system="Synthetic instruction.",
            prompt="Synthetic question.",
            settings=settings,
        ))

    assert error.value.code == "ai_endpoint_invalid"


@pytest.mark.parametrize("system,prompt", [
    ("", "Synthetic question."),
    ("Synthetic instruction.", ""),
    ("Synthetic instruction.", " \n\t "),
])
def test_generate_empty_prompt(
    monkeypatch, ai_settings, system, prompt
):
    prohibit_http_client(monkeypatch)

    with pytest.raises(OllamaUnavailable) as error:
        asyncio.run(generate(
            system=system,
            prompt=prompt,
            settings=ai_settings,
        ))

    assert error.value.code == "ai_prompt_invalid"


@pytest.mark.parametrize("prompt", [
    "x" * MAX_PROMPT_BYTES,
    "\u00e9" * (MAX_PROMPT_BYTES // 2),
])
def test_generate_oversized_prompt(
    monkeypatch, ai_settings, prompt
):
    prohibit_http_client(monkeypatch)

    with pytest.raises(OllamaUnavailable) as error:
        asyncio.run(generate(
            system="Synthetic instruction.",
            prompt=prompt,
            settings=ai_settings,
        ))

    assert error.value.code == "ai_context_too_large"


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_generate_redirect_rejected(
    monkeypatch, ai_settings, status
):
    calls = install_mock_transport(
        monkeypatch,
        lambda request: httpx.Response(
            status,
            headers={
                "Location": "https://example.test/api/generate"
            },
        ),
    )

    with pytest.raises(OllamaUnavailable) as error:
        asyncio.run(generate(
            system="Synthetic instruction.",
            prompt="Synthetic question.",
            settings=ai_settings,
        ))

    assert error.value.code == "ai_service_unavailable"
    assert len(calls) == 1


@pytest.mark.parametrize("encoding", [
    "gzip", "deflate", "br"
])
def test_generate_content_encoding_rejected(
    monkeypatch, ai_settings, encoding
):
    class UnreadableBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            pytest.fail("Encoded response body was read")
            yield b""

    calls = install_mock_transport(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            headers={"Content-Encoding": encoding},
            stream=UnreadableBody(),
        ),
    )

    with pytest.raises(OllamaUnavailable) as error:
        asyncio.run(generate(
            system="Synthetic instruction.",
            prompt="Synthetic question.",
            settings=ai_settings,
        ))

    assert error.value.code == "ai_response_invalid"
    assert len(calls) == 1


@pytest.mark.parametrize("content", [
    b'{"done": false, "done": true}',
    b'{"context": {"key": 1, "key": 2}}',
    b'{"value": NaN}',
    b'{"value": Infinity}',
    b'{"response": "\xff"}',
    b"[" * 2000 + b"0" + b"]" * 2000,
])
def test_generate_strict_json_rejection(
    monkeypatch, ai_settings, valid_response, content
):
    # Preserve otherwise valid response fields so that
    # malformed JSON cannot pass ordinary validation.
    prefix = json.dumps(valid_response).encode("utf-8")

    if content.startswith(b"{"):
        body = prefix[:-1] + b"," + content[1:]
    else:
        body = prefix[:-1] + b',"extra":' + content + b"}"

    calls = install_mock_transport(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            content=body,
        ),
    )

    with pytest.raises(OllamaUnavailable) as error:
        asyncio.run(generate(
            system="Synthetic instruction.",
            prompt="Synthetic question.",
            settings=ai_settings,
        ))

    assert error.value.code == "ai_response_invalid"
    assert len(calls) == 1


def test_generate_security_headers(
    monkeypatch, ai_settings, valid_response
):
    def handler(request):
        assert request.headers["Accept"] == "application/json"
        assert request.headers["Accept-Encoding"] == "identity"
        assert "Authorization" not in request.headers
        assert "Cookie" not in request.headers

        return httpx.Response(
            200,
            json=valid_response,
        )

    calls = install_mock_transport(monkeypatch, handler)

    result = asyncio.run(generate(
        system="Synthetic instruction.",
        prompt="Synthetic question.",
        settings=ai_settings,
    ))

    assert result["answer"] == valid_response["response"]
    assert len(calls) == 1


# Explicit JSON nesting boundary tests.

from app.ollama_client import (
    MAX_JSON_DEPTH,
    parse_response_json,
)


@pytest.mark.parametrize("depth", [
    MAX_JSON_DEPTH - 1,
    MAX_JSON_DEPTH,
])
def test_json_depth_boundary(depth):
    body = b"[" * depth + b"0" + b"]" * depth

    result = parse_response_json(body)

    for _ in range(depth):
        assert isinstance(result, list)
        assert len(result) == 1
        result = result[0]

    assert result == 0


def test_json_depth_above_limit():
    depth = MAX_JSON_DEPTH + 1

    body = b"[" * depth + b"0" + b"]" * depth

    with pytest.raises(OllamaUnavailable) as error:
        parse_response_json(body)

    assert error.value.code == "ai_response_invalid"


def test_json_depth_ignores_string_brackets():
    expected = {
        "response": "[" * 100 + "{" * 100
        + "]" * 100 + "}" * 100
    }

    body = json.dumps(expected).encode("utf-8")

    assert parse_response_json(body) == expected


def test_json_depth_handles_escaped_characters():
    expected = {
        "response": 'Quoted "text" with \\ and [brackets]',
        "context": [1, 2, 3],
    }

    body = json.dumps(expected).encode("utf-8")

    assert parse_response_json(body) == expected


def test_json_depth_rejects_unbalanced_structure():
    body = b'{"context": [1, 2, 3}'

    with pytest.raises(OllamaUnavailable) as error:
        parse_response_json(body)

    assert error.value.code == "ai_response_invalid"
