"""Validate assistant response shape and constrain navigation destinations."""
from __future__ import annotations

from typing import Any

ALLOWED_DESTINATIONS = {
    "dashboard", "devices", "scan_results", "operations",
    "activity_log", "certificates", "assistant", "settings",
}
MAX_ANSWER = 4000
MAX_CAVEATS = 5
MAX_NAVIGATION = 3


def validate_response(response: Any, request_id: str) -> dict[str, Any]:
    if not isinstance(response, dict):
        response = {}

    answer = response.get("answer")
    if not isinstance(answer, str) or not answer.strip():
        answer = (
            "I don't have enough reliable information to answer that yet. "
            "Check the relevant DataGuard screen for the current device or operation details."
        )
    answer = answer.strip()[:MAX_ANSWER]

    answer_type = response.get("answer_type")
    if not isinstance(answer_type, str) or not answer_type.strip():
        answer_type = "general_guidance"

    caveats = response.get("caveats", [])
    if not isinstance(caveats, list):
        caveats = []
    safe_caveats = [
        item.strip()[:500]
        for item in caveats[:MAX_CAVEATS]
        if isinstance(item, str) and item.strip()
    ]

    navigation = response.get("suggested_navigation", [])
    if not isinstance(navigation, list):
        navigation = []
    safe_navigation = []
    seen: set[str] = set()
    for item in navigation:
        if not isinstance(item, dict):
            continue
        destination = item.get("destination")
        label = item.get("label")
        if (
            not isinstance(destination, str)
            or destination not in ALLOWED_DESTINATIONS
            or destination in seen
            or not isinstance(label, str)
            or not label.strip()
        ):
            continue
        safe_navigation.append({
            "label": label.strip()[:80],
            "destination": destination,
        })
        seen.add(destination)
        if len(safe_navigation) >= MAX_NAVIGATION:
            break

    requires_action = response.get("requires_user_action", False)
    if not isinstance(requires_action, bool):
        requires_action = False

    # This service is guidance-only; it never returns executable operations.
    return {
        "request_id": request_id[:100],
        "answer": answer,
        "answer_type": answer_type[:80],
        "caveats": safe_caveats,
        "suggested_navigation": safe_navigation,
        "requires_user_action": requires_action,
        "source": "rule_based",
    }
