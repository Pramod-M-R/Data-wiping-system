"""Request validation and deterministic assistant orchestration."""
from __future__ import annotations

import json
import uuid
from typing import Any

try:
    from .context_builder import build_context
    from .intents import classify_intent
    from .policy import enforce_guidance_only
    from .response_validator import validate_response
    from .rules_engine import answer_question
except ImportError:  # executed as a local script by QProcess
    from context_builder import build_context
    from intents import classify_intent
    from policy import enforce_guidance_only
    from response_validator import validate_response
    from rules_engine import answer_question

MAX_REQUEST_BYTES = 20 * 1024
MAX_QUESTION_CHARS = 2000


class RequestError(ValueError):
    """Invalid assistant request."""


def handle_request(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise RequestError("The request must be a JSON object.")

    try:
        encoded = json.dumps(request, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RequestError("The request contains unsupported JSON values.") from exc
    if len(encoded) > MAX_REQUEST_BYTES:
        raise RequestError("The request is too large.")

    question = request.get("question")
    if not isinstance(question, str):
        raise RequestError("Question must be a string.")
    question = question.strip()
    if not question:
        raise RequestError("Please enter a question.")
    if len(question) > MAX_QUESTION_CHARS:
        raise RequestError(f"Question must be {MAX_QUESTION_CHARS} characters or fewer.")

    request_id = request.get("request_id")
    if not isinstance(request_id, str) or not request_id.strip():
        request_id = str(uuid.uuid4())
    request_id = request_id.strip()[:100]

    context = build_context(request.get("context"))
    intent = classify_intent(question)
    response = answer_question(question, intent, context)
    response = enforce_guidance_only(question, context, response)
    return validate_response(response, request_id)


def error_response(message: str, request_id: str = "") -> dict[str, Any]:
    return validate_response(
        {
            "answer": message,
            "answer_type": "request_error",
            "caveats": [],
            "suggested_navigation": [
                {"label": "Open Assistant", "destination": "assistant"}
            ],
            "requires_user_action": False,
            "source": "rule_based",
        },
        request_id or str(uuid.uuid4()),
    )
