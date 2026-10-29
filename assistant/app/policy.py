"""Non-bypassable guidance-only assistant policy."""
from __future__ import annotations

from typing import Any


def enforce_guidance_only(
    question: str, context: dict[str, Any], response: dict[str, Any]
) -> dict[str, Any]:
    """Ensure chat cannot authorize or initiate a storage operation."""
    text = question.casefold()
    direct_action = any(
        phrase in text
        for phrase in (
            "wipe it", "wipe this", "erase it", "erase this",
            "start wipe", "run wipe", "execute wipe", "perform wipe",
            "recover it", "recover this", "start recovery",
        )
    )
    if direct_action:
        response["caveats"] = list(response.get("caveats", []))
        response["caveats"].append(
            "The assistant cannot start a wipe or recovery. Use the application's normal workflow, validate the selected target, and approve its explicit confirmation dialog."
        )
        nav = list(response.get("suggested_navigation", []))
        if not any(
            isinstance(item, dict) and item.get("destination") == "operations"
            for item in nav
        ):
            nav.append({"label": "Open Operations", "destination": "operations"})
        response["suggested_navigation"] = nav
        response["requires_user_action"] = True
    return response
