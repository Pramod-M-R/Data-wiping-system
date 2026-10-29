"""Validate and minimize application context before assistant routing."""
from __future__ import annotations

from typing import Any

ALLOWED_SCREENS = {
    "dashboard", "devices", "scan_results", "operations",
    "activity_log", "certificates", "assistant", "settings",
}
MAX_TEXT = 320


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
    allowed = {"workflow", "wipe_method", "selected_file_count", "drive_name"}
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
        for item in files[:20]:
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
    for key in ("connected", "selected"):
        if isinstance(source.get(key), bool):
            result[key] = source[key]
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


def _scan_entry(source: Any) -> dict[str, Any]:
    if not isinstance(source, dict):
        return {}
    result = _copy_text_fields(
        source, ("file_name", "location", "status", "modified", "size_display")
    )
    size = _count(source.get("size_bytes"))
    if size is not None:
        result["size_bytes"] = size
    if isinstance(source.get("is_deleted"), bool):
        result["is_deleted"] = source["is_deleted"]
    return result


def _activity_record(source: Any) -> dict[str, Any]:
    if not isinstance(source, dict):
        return {}
    result = _copy_text_fields(
        source,
        (
            "timestamp", "user", "file_name", "location", "method", "status",
            "outcome", "verification", "ml_summary", "error_message",
            "certificate_id",
        ),
    )
    passes = _count(source.get("passes"))
    if passes is not None:
        result["passes"] = passes
    for key in ("certificate_available",):
        if isinstance(source.get(key), bool):
            result[key] = source[key]
    return result


def _settings(source: Any) -> dict[str, str]:
    return _copy_text_fields(source, ("signed_in_user", "persistence", "application_name"))


def _certificate(source: Any) -> dict[str, Any]:
    if not isinstance(source, dict):
        return {}
    result = _copy_text_fields(
        source,
        (
            "certificate_id", "timestamp", "user", "file_name", "location",
            "method", "status", "outcome", "verification", "ml_summary",
        ),
    )
    passes = _count(source.get("passes"))
    if passes is not None:
        result["passes"] = passes
    if isinstance(source.get("pdf_ready"), bool):
        result["pdf_ready"] = source["pdf_ready"]
    return result


def _bounded_objects(source: Any, limit: int, builder) -> list[dict[str, Any]]:
    if not isinstance(source, list):
        return []
    result = []
    for item in source[:limit]:
        clean = builder(item)
        if clean:
            result.append(clean)
    return result


def build_context(raw: Any) -> dict[str, Any]:
    """Return only allowlisted metadata; never pass file contents or credentials."""
    if not isinstance(raw, dict):
        raw = {}

    screen = _text(raw.get("screen"), 40).lower()
    if screen not in ALLOWED_SCREENS:
        screen = "unknown"

    context: dict[str, Any] = {"screen": screen}
    signed_in_user = _text(raw.get("signed_in_user"), 120)
    if signed_in_user:
        context["signed_in_user"] = signed_in_user
    settings = _settings(raw.get("settings"))
    if settings:
        context["settings"] = settings

    selected = _selected_operation(raw.get("selected_operation"))
    if selected:
        context["selected_operation"] = selected
    device = _device(raw.get("device"))
    if device:
        context["device"] = device

    devices = _bounded_objects(raw.get("devices"), 15, _device)
    if devices:
        context["devices"] = devices

    scan = _scan_summary(raw.get("scan_summary"))
    if scan:
        context["scan_summary"] = scan
    scan_entries = _bounded_objects(raw.get("scan_entries"), 100, _scan_entry)
    if scan_entries:
        context["scan_entries"] = scan_entries

    # Recent records are newest-first and intentionally bounded. The service can
    # answer history questions without receiving the complete permanent audit log.
    activity_records = _bounded_objects(raw.get("activity_records"), 30, _activity_record)
    if activity_records:
        context["activity_records"] = activity_records

    certificate_records = _bounded_objects(raw.get("certificate_records"), 25, _certificate)
    if certificate_records:
        context["certificate_records"] = certificate_records

    operation = _activity_record(raw.get("last_recorded_operation"))
    if operation:
        context["last_recorded_operation"] = operation
    certificate = _certificate(raw.get("certificate"))
    if certificate:
        context["certificate"] = certificate

    help_topic = _text(raw.get("help_topic"), 80)
    if help_topic:
        context["help_topic"] = help_topic
    return context
