"""Deterministic answers grounded in the current DataGuard snapshot."""
from __future__ import annotations

import re

from typing import Any

try:
    from .knowledge_base import load_knowledge
except ImportError:  # executed as a local script by QProcess
    from knowledge_base import load_knowledge


def _nav(label: str, destination: str) -> dict[str, str]:
    return {"label": label, "destination": destination}


def _result(
    answer: str,
    kind: str,
    caveats: list[str] | None = None,
    navigation: list[dict[str, str]] | None = None,
    requires_action: bool = False,
) -> dict[str, Any]:
    return {
        "answer": answer,
        "answer_type": kind,
        "caveats": caveats or [],
        "suggested_navigation": navigation or [],
        "requires_user_action": requires_action,
        "source": "rule_based",
    }


def _last_operation(context: dict[str, Any]) -> dict[str, Any]:
    value = context.get("last_recorded_operation")
    return value if isinstance(value, dict) else {}


def _format_operation(operation: dict[str, Any]) -> str:
    pieces = []
    labels = (
        ("file_name", "Target"),
        ("location", "Location"),
        ("method", "Wipe method"),
        ("outcome", "Recorded outcome"),
        ("status", "Recorded status"),
        ("timestamp", "Recorded time"),
        ("user", "Signed-in user"),
        ("verification", "Verification"),
        ("ml_summary", "ML analysis"),
        ("certificate_id", "Certificate ID"),
        ("error_message", "Error"),
    )
    for key, label in labels:
        value = operation.get(key)
        if isinstance(value, str) and value.strip():
            pieces.append(f"{label}: {value.strip()}")
    return "\n".join(pieces)

def _activity_records(context: dict[str, Any]) -> list[dict[str, Any]]:
    values = context.get("activity_records", [])
    if isinstance(values, list):
        records = [item for item in values if isinstance(item, dict)]
        if records:
            return records[:30]
    latest = _last_operation(context)
    return [latest] if latest else []


def _record_text(record: dict[str, Any]) -> str:
    return " ".join(
        str(record.get(key, ""))
        for key in ("file_name", "location", "certificate_id", "error_message", "method", "outcome")
    ).casefold()


def _pick_relevant_record(question: str, records: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not records:
        return None
    tokens = re.findall(r"[a-z0-9][a-z0-9._-]+", question.casefold())
    stop = {
        "which", "what", "file", "files", "drive", "target", "item", "did", "do", "i",
        "just", "wipe", "wiped", "wiping", "erase", "erased", "delete", "deleted", "the",
        "my", "me", "was", "were", "have", "has", "who", "last", "latest", "recent",
        "previous", "show", "list", "tell", "and", "or", "for", "from", "to", "in",
        "activity", "log", "history", "operation", "operations", "result", "status",
    }
    needles = [token for token in tokens if token not in stop and len(token) >= 3]
    if needles:
        ranked: list[tuple[int, int, dict[str, Any]]] = []
        for index, record in enumerate(records):
            haystack = _record_text(record)
            hits = sum(1 for token in needles if token in haystack)
            if hits:
                ranked.append((hits, -index, record))
        if ranked:
            ranked.sort(key=lambda row: (row[0], row[1]), reverse=True)
            return ranked[0][2]
    return records[0]


def _format_history_record(record: dict[str, Any]) -> str:
    fields = (
        ("file_name", "File / drive"),
        ("location", "Location"),
        ("method", "Wipe method"),
        ("outcome", "Outcome"),
        ("timestamp", "Date and time"),
        ("user", "Signed-in user"),
        ("verification", "Verification"),
        ("certificate_id", "Certificate ID"),
    )
    lines = []
    for key, label in fields:
        value = record.get(key)
        if isinstance(value, str) and value.strip() and value.strip() != "—":
            lines.append(f"{label}: {value.strip()}")
    return "\n".join(lines)


def _history_answer(question: str, context: dict[str, Any]) -> dict[str, Any]:
    records = _activity_records(context)
    if not records:
        return _result(
            "There are no wipe records available in the current Activity Log context, so I can't identify a file that was just wiped. Perform or review the operation in DataGuard, then refresh Activity Log and ask again.",
            "history_lookup",
            navigation=[_nav("Open Activity Log", "activity_log"), _nav("Open Certificates", "certificates")],
        )

    q = question.casefold()
    wants_multiple = any(term in q for term in (
        "files", "all", "list", "history", "activity log", "recent operations",
        "recent wipes", "which ones", "what ones", "records",
    ))
    if wants_multiple:
        entries = []
        for index, record in enumerate(records[:5], start=1):
            name = str(record.get("file_name", "")).strip() or "Target not recorded"
            location = str(record.get("location", "")).strip()
            outcome = str(record.get("outcome", record.get("status", "Outcome not recorded"))).strip()
            timestamp = str(record.get("timestamp", "")).strip()
            method = str(record.get("method", "")).strip()
            line = f"{index}. {name}"
            if location:
                line += f" — {location}"
            line += f"\n   {outcome}"
            if method:
                line += f" | {method}"
            if timestamp:
                line += f" | {timestamp}"
            entries.append(line)
        answer = "Here are the most recent records visible to the assistant from Activity Log, newest first:\n" + "\n".join(entries)
        answer += "\n\nThis is a recent-history window, not necessarily the complete lifetime log."
        return _result(
            answer,
            "history_lookup",
            caveats=["Outcomes and verification are reported from the saved DataGuard activity records."],
            navigation=[_nav("Open Activity Log", "activity_log"), _nav("Open Certificates", "certificates")],
        )

    selected = _pick_relevant_record(question, records)
    if selected is None:
        return _result("No matching activity record is available.", "history_lookup")
    details = _format_history_record(selected)
    if not details:
        details = "The record exists, but the saved entry contains no readable file, time, or outcome details."
    answer = "The most relevant recorded operation in Activity Log is:\n" + details
    ml_summary = selected.get("ml_summary")
    if any(term in q for term in ("ml", "similarity", "recoverability", "risk", "score")) and ml_summary:
        answer += f"\nML analysis recorded for this operation:\n{ml_summary}"
    answer += "\n\nI'm reading the saved activity record; I did not infer a wipe from the chat message."
    return _result(
        answer,
        "history_lookup",
        caveats=["A saved operation status and its verification result are different facts."],
        navigation=[_nav("Open Activity Log", "activity_log"), _nav("Open Certificate", "certificates")],
    )




def answer_question(
    question: str, intent: str, context: dict[str, Any]
) -> dict[str, Any]:
    q = question.casefold()
    screen = context.get("screen", "unknown")
    device = context.get("device", {})
    scan = context.get("scan_summary", {})
    selected = context.get("selected_operation", {})
    operation = _last_operation(context)
    certificate = context.get("certificate", {})
    knowledge = load_knowledge()

    if intent == "greeting":
        return _result(
            "Hello! I'm the DataGuard Assistant. I can explain the current scan, device information, wipe methods, recorded operation results, ML estimates, and certificates. I can guide you to a screen, but I cannot run a wipe or recovery for you.",
            "greeting",
            navigation=[_nav("Review Scan Results", "scan_results"), _nav("View Activity Log", "activity_log")],
        )

    if intent == "help":
        return _result(
            "I can help you understand device and scan summaries, explain wipe-method trade-offs, interpret a recorded error or verification result, and find a certificate. My answers use only the current application snapshot and approved local help. If a value is unavailable, I'll say so rather than guess.",
            "help",
            caveats=["I provide guidance only; all storage actions must be performed in the application's normal validated workflow."],
            navigation=[_nav("Devices", "devices"), _nav("Scan Results", "scan_results"), _nav("Certificates", "certificates")],
        )

    if intent == "history_lookup":
        return _history_answer(question, context)

    if intent == "destructive_request":
        return _result(
            "I cannot execute a wipe or recovery from chat. To continue safely, open Operations, confirm the selected USB drive and exact target, verify your backup, then use the application's normal confirmation dialog. If you are unsure about the target, cancel and review Scan Results first.",
            "safety_guidance",
            caveats=["Wiping is destructive. Chat text cannot bypass target validation, permissions, or confirmation."],
            navigation=[_nav("Review Scan Results", "scan_results"), _nav("Open Operations", "operations")],
            requires_action=True,
        )

    if intent == "device_info":
        inventory = context.get("devices", [])
        wants_inventory = any(term in q for term in (
            "devices", "how many", "list", "all usb", "which usb", "connected drives",
        ))
        if wants_inventory and isinstance(inventory, list) and inventory:
            descriptions = []
            for item in inventory[:10]:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("display_name", "USB drive"))
                letter = str(item.get("drive_letter", ""))
                model = str(item.get("model", ""))
                size = item.get("capacity_bytes")
                detail = name
                if letter and letter not in name:
                    detail += f" ({letter})"
                if model:
                    detail += f" — {model}"
                if isinstance(size, int):
                    detail += f", {size / (1024 ** 3):.2f} GiB"
                if item.get("selected"):
                    detail += " [currently selected]"
                descriptions.append(detail)
            return _result(
                "Removable devices reported by the current application snapshot:\n" + "\n".join(f"• {item}" for item in descriptions),
                "device_inventory",
                caveats=["Recheck the physical device identity before any destructive operation."],
                navigation=[_nav("Open Devices", "devices")],
            )
        if not isinstance(device, dict) or not device:
            inventory = context.get("devices", [])
            if isinstance(inventory, list) and inventory:
                return _result(
                    "DataGuard currently reports " + str(len(inventory)) + " removable device(s). Ask me to list connected devices, or open Devices to select one for more specific details.",
                    "device_inventory",
                    navigation=[_nav("Open Devices", "devices")],
                )
            return _result(
                "No selected-device details are available in the current application context. Open Devices, refresh the device list, and select the intended drive. I won't assume a device is connected from an earlier message.",
                "device_information",
                navigation=[_nav("Open Devices", "devices")],
                requires_action=True,
            )
        if device.get("connected") is False:
            return _result(
                "The current snapshot marks the selected device as disconnected. Refresh Devices and select a currently connected device before continuing.",
                "device_information",
                navigation=[_nav("Refresh Devices", "devices")],
                requires_action=True,
            )
        parts = []
        if device.get("display_name"):
            parts.append(f"Selected device: {device['display_name']}.")
        if device.get("model"):
            parts.append(f"Reported model: {device['model']}.")
        if device.get("drive_letter"):
            parts.append(f"Drive letter: {device['drive_letter']}.")
        if isinstance(device.get("capacity_bytes"), int):
            parts.append(f"Reported capacity: {device['capacity_bytes'] / (1024 ** 3):.2f} GiB.")
        if device.get("filesystem"):
            parts.append(f"Filesystem: {device['filesystem']}.")
        else:
            parts.append("The current application snapshot does not report the filesystem.")
        parts.append("Recheck the drive identity in Devices before any destructive operation.")
        return _result(
            " ".join(parts),
            "device_information",
            caveats=["A selected-device label is context, not a substitute for confirming the physical target."],
            navigation=[_nav("Open Devices", "devices")],
        )

    if intent == "scan_explanation":
        if not isinstance(scan, dict) or not scan:
            return _result(
                "There is no current scan summary available. Select the intended drive in Devices, run Scan Selected Drive, and then ask again. I won't reuse a previous assistant message as evidence of a current scan.",
                "scan_explanation",
                navigation=[_nav("Open Devices", "devices"), _nav("Review Scan Results", "scan_results")],
                requires_action=True,
            )
        counts = []
        for key, label in (
            ("existing_entries", "existing entries"),
            ("potentially_deleted_entries", "potentially deleted entries"),
            ("hidden_entries", "hidden entries"),
        ):
            if key in scan:
                counts.append(f"{scan[key]} {label}")
        status = scan.get("scan_status", "not supplied")
        answer = "Current scan summary: " + (", ".join(counts) if counts else "entry counts were not supplied") + f". Scan status: {status}."
        deleted_count = scan.get("potentially_deleted_entries", 0)
        caveats = list(scan.get("limitations", []))
        if isinstance(deleted_count, int) and deleted_count > 0:
            answer += " A deleted directory entry is only a candidate; it does not prove that the original contents are intact or recoverable."
            caveats.append("Results depend on filesystem support, available metadata, and scan coverage.")
            faq_scan = knowledge.get("faq", {}).get("scan", "")
            if isinstance(faq_scan, str) and faq_scan:
                caveats.append(faq_scan)
        if "error" in scan:
            answer += f" Scanner message: {scan['error']}."
        scan_entries = context.get("scan_entries", [])
        wants_file_list = any(term in q for term in (
            "which files", "what files", "list files", "show files", "file names",
            "which entries", "what entries", "show me the files", "files found",
        ))
        if wants_file_list and isinstance(scan_entries, list) and scan_entries:
            lines = []
            for item in scan_entries[:10]:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("file_name", "")).strip()
                if not name:
                    continue
                location = str(item.get("location", "")).strip()
                status = str(item.get("status", "")).strip()
                line = name
                if status:
                    line += f" [{status}]"
                if location:
                    line += f" — {location}"
                lines.append(line)
            if lines:
                answer += "\n\nFiles and entries present in the current scan snapshot:\n" + "\n".join(f"• {line}" for line in lines)
                if len(scan_entries) > len(lines):
                    answer += "\nShowing only a subset of the scan entries."
        return _result(
            answer,
            "scan_explanation",
            caveats=caveats,
            navigation=[_nav("Review Scan Results", "scan_results")],
        )

    if intent in {"ml_explanation", "verification", "operation_status"}:
        relevant_operation = _pick_relevant_record(question, _activity_records(context))
        if relevant_operation:
            operation = relevant_operation

    if intent == "ml_explanation":
        summary = operation.get("ml_summary", "")
        if not summary:
            summary = certificate.get("ml_summary", "") if isinstance(certificate, dict) else ""
        if not summary:
            return _result(
                "No ML analysis summary was supplied for the current operation or selected certificate. I won't calculate or invent similarity or recoverability percentages. Open Activity Log or Certificates to inspect the recorded result.",
                "ml_explanation",
                caveats=["ML scores are estimates and do not by themselves prove recoverability or permanent irrecoverability."],
                navigation=[_nav("Open Activity Log", "activity_log"), _nav("Open Certificates", "certificates")],
            )
        return _result(
            f"Recorded ML summary:\n{summary}\n\nThese values are the application's recorded output, not an independent measurement by the assistant.",
            "ml_explanation",
            caveats=[
                knowledge.get("faq", {}).get("ml", "Treat ML scores as estimates, not guarantees."),
                "The assistant repeats the application's recorded result and does not independently calculate missing scores.",
            ],
            navigation=[_nav("Open Activity Log", "activity_log"), _nav("Open Certificates", "certificates")],
        )

    if intent in {"verification", "operation_status"}:
        formatted = _format_operation(operation)
        if not formatted:
            formatted = _format_operation(certificate)
        if not formatted:
            return _result(
                "I don't have a recorded operation result in the current context, so I can't say whether a wipe completed or verification passed. Open Activity Log and select the relevant record.",
                "operation_status",
                navigation=[_nav("Open Activity Log", "activity_log")],
            )
        result = (
            "Here is the operation information recorded by DataGuard:\n"
            f"{formatted}\n\n"
            "A successful execution status and a successful verification are different claims. The recorded verification field shows what the application reported; it is not a blanket guarantee of irrecoverability."
        )
        return _result(
            result,
            "verification_explanation" if intent == "verification" else "operation_status",
            caveats=[
                "The assistant does not independently verify the storage device.",
                *[
                    item for item in knowledge.get("verification_limits", {}).get("principles", [])[:3]
                    if isinstance(item, str)
                ],
            ],
            navigation=[_nav("Open Activity Log", "activity_log"), _nav("Open Certificates", "certificates")],
        )

    if intent == "certificate":
        if not isinstance(certificate, dict) or not certificate:
            available = context.get("certificate_records", [])
            if isinstance(available, list) and available:
                lines = []
                for item in available[:6]:
                    if not isinstance(item, dict):
                        continue
                    certificate_id = str(item.get("certificate_id", "")).strip()
                    file_name = str(item.get("file_name", "")).strip()
                    timestamp = str(item.get("timestamp", "")).strip()
                    outcome = str(item.get("outcome", item.get("status", ""))).strip()
                    pdf_ready = item.get("pdf_ready") is True
                    line = certificate_id or "Certificate ID not recorded"
                    if file_name:
                        line += f" — {file_name}"
                    if timestamp:
                        line += f" — {timestamp}"
                    if outcome:
                        line += f" — {outcome}"
                    line += " — PDF ready" if pdf_ready else " — PDF unavailable or not verified"
                    lines.append(line)
                return _result(
                    "Recent certificate records supplied by DataGuard, newest first:\\n" + "\\n".join(f"• {line}" for line in lines),
                    "certificate_list",
                    caveats=["Select a row in Certificates to ask for that certificate's full recorded details."],
                    navigation=[_nav("Open Certificates", "certificates")],
                )
            return _result(
                "No certificate records are available in the current application context. Open Certificates and refresh the list; I won't assume a certificate exists without a saved record.",
                "certificate_guidance",
                navigation=[_nav("Open Certificates", "certificates")],
                requires_action=True,
            )
        values = []
        for key, label in (
            ("certificate_id", "Certificate ID"),
            ("timestamp", "Date and time"),
            ("user", "Signed-in user"),
            ("file_name", "File or drive"),
            ("location", "Location"),
            ("method", "Wipe method"),
            ("status", "Recorded outcome"),
            ("verification", "Verification"),
            ("ml_summary", "ML analysis"),
        ):
            value = certificate.get(key)
            if value:
                values.append(f"{label}: {value}")
        return _result(
            "Certificate information supplied by the application:\n" + "\n".join(values) +
            "\n\nThe certificate records application-reported details; its assurance is limited to the checks actually performed and recorded.",
            "certificate_explanation",
            caveats=[
                knowledge.get("faq", {}).get("certificate", "A certificate is limited to the checks performed and recorded."),
                "A certificate alone is not a universal guarantee that all copies of data are permanently irrecoverable.",
            ],
            navigation=[_nav("Open Certificates", "certificates")],
        )

    if intent == "error":
        errors = knowledge.get("known_errors", {})
        recorded_error = operation.get("error_message", "")
        matched = None
        if isinstance(errors, dict):
            candidates = []
            if recorded_error:
                candidates.append(recorded_error.casefold())
            candidates.append(q)
            for pattern, entry in errors.items():
                if not isinstance(pattern, str) or not isinstance(entry, dict):
                    continue
                if any(pattern.casefold() in candidate for candidate in candidates):
                    matched = entry
                    break
        if matched:
            explanation = matched.get("explanation", "")
            steps = matched.get("safe_steps", [])
            answer = explanation or "The application recorded an error, but there is not enough context to identify the exact cause."
            if isinstance(steps, list) and steps:
                answer += "\nSafe next steps:\n" + "\n".join(f"• {step}" for step in steps[:4] if isinstance(step, str))
        elif recorded_error:
            answer = f"The latest recorded operation error is: {recorded_error}. The available context does not establish a more specific cause. Do not repeat a destructive operation until the target and error are understood."
        else:
            answer = "I don't have a matching recorded error or error code in the current context. Please open Activity Log or the operation result and use the exact message; I won't guess the cause."
        return _result(
            answer,
            "error_explanation",
            caveats=["If a suggested step could risk data loss, stop and get help rather than retrying the wipe."],
            navigation=[_nav("Open Activity Log", "activity_log"), _nav("Review Scan Results", "scan_results")],
        )

    if intent == "recovery_file_guidance":
        workflow = knowledge.get("operations", {}).get("recover_file", {})
        workflow_note = workflow.get("description", "")
        answer = (
            "For file recovery, review the specific candidate and its scan details before proceeding. "
            "Avoid writing new data to the source drive because it may overwrite remnants, and use a destination on a different device. "
            "A deleted entry or file signature does not prove the file's contents can be recovered, and this context does not confirm that a recovery workflow is enabled in this build."
        )
        if isinstance(workflow_note, str) and workflow_note:
            answer += " Application guidance: " + workflow_note
        return _result(
            answer,
            "file_recovery_guidance",
            caveats=["Do not save recovered output back to the source device when preserving other recoverable data matters."],
            navigation=[_nav("Review Scan Results", "scan_results"), _nav("Open Devices", "devices")],
            requires_action=True,
        )

    if intent == "recovery_drive_guidance":
        workflow = knowledge.get("operations", {}).get("recover_drive", {})
        workflow_note = workflow.get("description", "")
        answer = (
            "For drive recovery, first review the supported scan result for the intended source device. "
            "Avoid writing to the source and use a separate destination device for recovered output. "
            "Scan coverage and filesystem support limit what may be found; this context does not confirm that a full-drive recovery workflow is enabled, so I cannot promise that all files can be restored."
        )
        if isinstance(workflow_note, str) and workflow_note:
            answer += " Application guidance: " + workflow_note
        return _result(
            answer,
            "drive_recovery_guidance",
            caveats=["Do not overwrite the source drive while attempting recovery."],
            navigation=[_nav("Open Devices", "devices"), _nav("Review Scan Results", "scan_results")],
            requires_action=True,
        )

    if intent == "recovery_guidance":
        return _result(
            "Avoid writing new data to the source drive if recovery matters, because new writes can overwrite remnants. Review scan candidates and use a separate destination for any recovered files. The current context does not confirm an enabled recovery workflow, so I can't promise that this build can restore a particular file.",
            "recovery_guidance",
            caveats=["A deleted entry or file signature does not prove its contents can be recovered."],
            navigation=[_nav("Review Scan Results", "scan_results"), _nav("Open Devices", "devices")],
        )

    
    if intent == "operation_selection":
        if any(term in q for term in (
            "everything", "all data", "entire drive", "whole drive", "full drive",
            "entire usb", "whole usb", "full usb", "entire disk", "whole disk",
        )):
            workflow = knowledge.get("operations", {}).get("full_drive_wipe", {})
            workflow_note = workflow.get("description", "")
            answer = workflow_note if isinstance(workflow_note, str) and workflow_note else (
                "The full-drive wipe workflow can destroy data on the selected device. Confirm the drive identity and back up anything you need."
            )
            answer += " The assistant will not start the wipe; use the application's normal confirmation dialog."
            return _result(
                answer,
                "operation_guidance",
                caveats=["Do not proceed if the selected drive, its capacity, or its identity is uncertain."],
                navigation=[_nav("Open Devices", "devices"), _nav("Open Operations", "operations")],
                requires_action=True,
            )
        workflow = knowledge.get("operations", {}).get("single_file_wipe", {})
        workflow_note = workflow.get("description", "")
        answer = (
            "For one particular file, review the exact entry in Scan Results and use the application's file-selection workflow. "
            "For the full USB drive, the full-drive wipe is a separate destructive workflow. This assistant cannot select a target or start either operation."
        )
        if isinstance(workflow_note, str) and workflow_note:
            answer += " Application guidance: " + workflow_note
        return _result(
            answer,
            "operation_guidance",
            caveats=["Per-file erasure reliability depends on filesystem metadata and storage technology."],
            navigation=[_nav("Review Scan Results", "scan_results"), _nav("Open Operations", "operations")],
            requires_action=True,
        )

    if intent == "wipe_guidance":
        method = selected.get("wipe_method", "")
        if "method" in q or "single pass" in q or "dod" in q or "pass" in q:
            method_text = f"The currently selected wipe method is {method}. " if method else "No selected wipe method was supplied in the current context. "
            return _result(
                method_text +
                "Single-pass, DoD 3-pass and DoD 7-pass describe different overwrite patterns in this application's menu. More passes mean more overwrite work, but they do not by themselves guarantee erasure across remapped or flash storage areas.",
                "wipe_method_guidance",
                caveats=["Confirm the target and method in Operations before proceeding."],
                navigation=[_nav("Open Operations", "operations")],
            )
        return _result(
            "Wiping is destructive. Select the intended file or drive in the existing workflow, check its identity, and use the confirmation dialog. A successful overwrite and an independent verification result are separate facts.",
            "wipe_guidance",
            caveats=["The assistant cannot initiate wipes, skip confirmation, or establish permanent irrecoverability."],
            navigation=[_nav("Open Operations", "operations"), _nav("Open Activity Log", "activity_log")],
        )

    if intent == "navigation":
        routes = (
            ("dashboard", ("dashboard",)),
            ("devices", ("devices",)),
            ("scan_results", ("scan",)),
            ("operations", ("operations",)),
            ("activity_log", ("activity log", "history")),
            ("certificates", ("certificates",)),
            ("assistant", ("assistant",)),
            ("settings", ("settings",)),
        )
        for destination, terms in routes:
            if any(term in q for term in terms):
                return _result(
                    f"You can open {destination.replace('_', ' ').title()} using the navigation panel.",
                    "navigation_guidance",
                    navigation=[_nav(f"Open {destination.replace('_', ' ').title()}", destination)],
                )

    if intent == "device_info" or intent == "scan_explanation":
        return _result(
            "The current context does not contain enough information to answer that specifically. Open the relevant device or scan screen and ask again.",
            "missing_context",
            navigation=[_nav("Open Devices", "devices"), _nav("Review Scan Results", "scan_results")],
        )

    return _result(
        "I don't have enough approved application context to answer that reliably yet. Try asking about the current scan, selected device, wipe methods, a recorded error, verification, or a certificate. You can also open the relevant screen and ask again.",
        "unknown",
        caveats=["I won't invent device state, scan counts, ML values, operation outcomes, or certificates."],
        navigation=[_nav("Ask for help", "assistant"), _nav("Review Scan Results", "scan_results")],
    )
