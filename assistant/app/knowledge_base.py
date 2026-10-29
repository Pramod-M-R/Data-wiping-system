"""Load version-controlled, approved assistant knowledge."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_KNOWLEDGE_DIR = Path(__file__).resolve().parents[1] / "knowledge"
_FILES = ("faq.json", "operations.json", "known_errors.json", "verification_limits.json")


@lru_cache(maxsize=1)
def load_knowledge() -> dict[str, Any]:
    """Load only local JSON knowledge; never fetch remote instructions."""
    result: dict[str, Any] = {}
    for file_name in _FILES:
        path = _KNOWLEDGE_DIR / file_name
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                result[file_name.removesuffix(".json")] = data
        except (OSError, json.JSONDecodeError):
            # A missing knowledge file must not crash the application.
            result[file_name.removesuffix(".json")] = {}
    return result
