"""Validate and minimize application context before assistant routing."""
from __future__ import annotations

from typing import Any

ALLOWED_SCREENS = {
    "dashboard", "devices", "scan_results", "operations",
    "activity_log", "certificates", "assistant", "settings",
}
MAX_TEXT = 320
MAX_QUESTION_CONTEXT_TEXT = 1200


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().replace("\x00", "")[:limit]


def _count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _copy_text_fields(source: Any, fields: tuple[str, ...]) -> dict[str, str]:
    if not isinstance(source, dict):
        return {}
    result: dict[str, str] = {}
    for field in fields:
        value = _text(source.get(field))
        if value:
            result[field] = value
    return result


def _selected_operation(source: Any) -> dict[str, Any]:
    if not isinstance(source, dict):
        return {}
    allowed = {"workflow", "wipe_method", "selected_file_count"}
    result: dict[str, Any] = {}
    for key in allowed:
        value = source.get(key)
        if key == "selected_file_count":
            count = _count(value)
            if count is not None:
                result[key] = count
        else:
            clean = _text(value)
            if clean:
                result[key] = clean

    files = source.get("selected_files")
    if isinstance(files, list):
        cleaned_files = []
        for item in files[:10]:
            if not isinstance(item, dict):
                continue
            entry: dict[str, Any] = {}
            name = _text(item.get("file_name"), 180)
            if name:
                entry["file_name"] = name
            if isinstance(item.get("is_deleted"), bool):
                entry["is_deleted"] = item["is_deleted"]
            size = _count(item.get("size_bytes"))
            if size is not None:
                entry["size_bytes"] = size
            if entry:
                cleaned_files.append(entry)
        if cleaned_files:
            result["selected_files"] = cleaned_files
    return result


def _device(source: Any) -> dict[str, Any]:
    result = _copy_text_fields(
        source, ("display_name", "model", "filesystem", "drive_letter")
    )
    if not isinstance(source, dict):
        return result
    if isinstance(source.get("connected"), bool):
        result["connected"] = source["connected"]
    capacity = _count(source.get("capacity_bytes"))
    if capacity is not None:
        result["capacity_bytes"] = capacity
    return result


def _scan_summary(source: Any) -> dict[str, Any]:
    if not isinstance(source, dict):
        return {}
    result: dict[str, Any] = {}
    for key in ("existing_entries", "potentially_deleted_entries", "hidden_entries"):
        count = _count(source.get(key))
        if count is not None:
            result[key] = count
    for key in ("scan_status", "error"):
        value = _text(source.get(key))
        if value:
            result[key] = value
    limitations = source.get("limitations")
    if isinstance(limitations, list):
        clean = [_text(item, 240) for item in limitations[:5]]
        clean = [item for item in clean if item]
        if clean:
            result["limitations"] = clean
    return result


def _operation(source: Any) -> dict[str, Any]:
    if not isinstance(source, dict):
        return {}
    result = _copy_text_fields(
        source,
        (
            "timestamp", "file_name", "source", "method", "status",
            "verification", "error_message", "ml_summary", "certificate_id",
        ),
    )
    bytes_wiped = _count(source.get("bytes_wiped"))
    if bytes_wiped is not None:
        result["bytes_wiped"] = bytes_wiped
    return result


def _certificate(source: Any) -> dict[str, Any]:
    if not isinstance(source, dict):
        return {}
    result = _copy_text_fields(
        source,
        (
            "certificate_id", "timestamp", "user", "file_name", "location",
            "method", "status", "verification", "ml_summary",
        ),
    )
    passes = _count(source.get("passes"))
    if passes is not None:
        result["passes"] = passes
    return result


def build_context(raw: Any) -> dict[str, Any]:
    """Return only allowlisted metadata; never pass file contents or credentials."""
    if not isinstance(raw, dict):
        raw = {}

    screen = _text(raw.get("screen"), 40).lower()
    if screen not in ALLOWED_SCREENS:
        screen = "unknown"

    context: dict[str, Any] = {"screen": screen}
    selected = _selected_operation(raw.get("selected_operation"))
    if selected:
        context["selected_operation"] = selected
    device = _device(raw.get("device"))
    if device:
        context["device"] = device
    scan = _scan_summary(raw.get("scan_summary"))
    if scan:
        context["scan_summary"] = scan
    operation = _operation(raw.get("last_recorded_operation"))
    if operation:
        context["last_recorded_operation"] = operation
    certificate = _certificate(raw.get("certificate"))
    if certificate:
        context["certificate"] = certificate

    help_topic = _text(raw.get("help_topic"), 80)
    if help_topic:
        context["help_topic"] = help_topic
    return context
