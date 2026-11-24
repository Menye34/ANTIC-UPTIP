"""Restricted communication with the local Ollama service."""

import asyncio
import json

import httpx

from .config import Settings, get_settings


MAX_RESPONSE_BYTES = 65536
MAX_PROMPT_BYTES = 16384


class OllamaUnavailable(Exception):
    """Controlled local AI service failure."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


MAX_ANSWER_CHARACTERS = 6000


def reject_duplicate_keys(pairs):
    """Reject ambiguous JSON objects."""
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")

        result[key] = value

    return result


def reject_json_constant(value):
    """Reject non-standard JSON numeric constants."""
    raise ValueError("Invalid JSON constant")


MAX_JSON_DEPTH = 32


def validate_json_depth(text: str):
    """Reject excessive JSON nesting before parsing."""
    depth = 0
    in_string = False
    escaped = False

    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char in ("{", "["):
            depth += 1

            if depth > MAX_JSON_DEPTH:
                raise OllamaUnavailable(
                    "ai_response_invalid"
                )
        elif char in ("}", "]"):
            depth -= 1

            if depth < 0:
                raise OllamaUnavailable(
                    "ai_response_invalid"
                )

    if depth != 0 or in_string:
        raise OllamaUnavailable(
            "ai_response_invalid"
        )


def parse_response_json(body: bytes | bytearray):
    """Decode strict UTF-8 JSON with controlled failures."""
    try:
        text = body.decode("utf-8", errors="strict")
        validate_json_depth(text)

        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )
    except (ValueError, UnicodeError, RecursionError):
        raise OllamaUnavailable(
            "ai_response_invalid"
        ) from None


def validate_response(result: dict, settings: Settings) -> dict:
    """Accept only complete, bounded responses from the configured model."""

    if not isinstance(result, dict):
        raise OllamaUnavailable("ai_response_invalid")

    if "error" in result:
        raise OllamaUnavailable("ai_service_unavailable")

    if result.get("model") != settings.ai_model:
        raise OllamaUnavailable("ai_model_mismatch")

    if result.get("done") is not True:
        raise OllamaUnavailable("ai_response_incomplete")

    if result.get("done_reason") != "stop":
        raise OllamaUnavailable("ai_response_incomplete")

    answer = result.get("response")

    if not isinstance(answer, str) or not answer.strip():
        raise OllamaUnavailable("ai_response_empty")

    if len(answer) > MAX_ANSWER_CHARACTERS:
        raise OllamaUnavailable("ai_response_too_large")

    if any(
        not char.isprintable() and ord(char) not in (9, 10)
        for char in answer
    ):
        raise OllamaUnavailable("ai_response_invalid")

    output_tokens = result.get("eval_count")

    if (
        type(output_tokens) is not int
        or output_tokens < 1
        or output_tokens > settings.ai_max_output_tokens
    ):
        raise OllamaUnavailable("ai_response_invalid")

    return {
        "answer": answer.strip(),
        "model": settings.ai_model,
        "output_tokens": output_tokens,
    }


async def generate(
    *,
    system: str,
    prompt: str,
    settings: Settings | None = None,
) -> dict:
    """Request a bounded response from the local model."""

    settings = settings or get_settings()

    if not settings.ai_enabled:
        raise OllamaUnavailable("ai_disabled")

    if settings.ai_base_url != "http://127.0.0.1:11434":
        raise OllamaUnavailable("ai_endpoint_invalid")

    if not system.strip() or not prompt.strip():
        raise OllamaUnavailable("ai_prompt_invalid")

    if len((system + prompt).encode("utf-8")) > MAX_PROMPT_BYTES:
        raise OllamaUnavailable("ai_context_too_large")

    payload = {
        "model": settings.ai_model,
        "system": system,
        "prompt": prompt,
        "stream": False,
        "keep_alive": settings.ai_keep_alive,
        "options": {
            "temperature": 0.2,
            "num_ctx": settings.ai_context_tokens,
            "num_predict": settings.ai_max_output_tokens,
            "num_thread": settings.ai_threads,
        },
    }

    timeout = httpx.Timeout(
        float(settings.ai_timeout_seconds),
        connect=5.0,
    )

    try:
        async with asyncio.timeout(settings.ai_timeout_seconds):
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream(
                    "POST",
                    settings.ai_base_url + "/api/generate",
                    json=payload,
                    headers={
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                    },
                ) as response:
                    if response.status_code != 200:
                        raise OllamaUnavailable(
                            "ai_service_unavailable"
                        )

                    encoding = response.headers.get(
                        "Content-Encoding", "identity"
                    ).strip().lower()

                    if encoding != "identity":
                        raise OllamaUnavailable(
                            "ai_response_invalid"
                        )

                    body = bytearray()

                    async for chunk in response.aiter_bytes(
                        chunk_size=4096
                    ):
                        if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                            raise OllamaUnavailable(
                                "ai_response_too_large"
                            )

                        body.extend(chunk)

    except (TimeoutError, httpx.TimeoutException):
        raise OllamaUnavailable("ai_timeout") from None

    except httpx.HTTPError:
        raise OllamaUnavailable(
            "ai_service_unavailable"
        ) from None

    result = parse_response_json(body)

    return validate_response(result, settings)
