"""Conservative intent routing for the offline rule-based assistant."""
from __future__ import annotations

import re

_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    # Resolve certificate-specific questions before the broader "prove/verification" intent.
    ("certificate", (
        r"\b(certificate|pdf|proof of wipe|wipe proof|certificate id)\b",
    )),
    # Route explicit whole-drive goals to guidance rather than the generic destructive-request response.
    ("operation_selection", (
        r"\b(which operation|what should i choose|which workflow|want to erase everything|wipe everything|"
        r"want to wipe (the )?(usb|drive|disk)|wipe (the )?(entire|whole|full) (drive|usb|disk)|"
        r"erase (the )?(entire|whole|full) (drive|usb|disk)|erase all data)\b",
    )),
    ("history_lookup", (
        r"\b(which|what)\s+(file|files|drive|drives|target|item|items)\b.{0,60}\b(did i|was|were|have i|have we)\b.{0,35}\b(wipe|wiped|erase|erased|delete|deleted)\b",
        r"\b(who|which user)\b.{0,60}\b(wiped|erased|deleted|performed)\b",
        r"\bwhat did i (just )?(wipe|erase|delete)\b",
        r"\b(last|latest|recent|previous)\b.{0,40}\b(wipe|erasure|operation|file|activity|certificate)\b",
        r"\b(activity log|wipe history|operation history|recent activity|my last wipe|last file i wiped|which files have i wiped)\b",
    )),
    ("destructive_request", (
        r"\b(wipe|erase|destroy)\s+(it|this|that|the file|the drive|everything|all data)\b",
        r"\b(start|run|execute|perform|initiate)\s+(the\s+)?(wipe|erasure|recovery)\b",
        r"\bdelete\s+(it|this file|that file)\b",
    )),
    ("recovery_drive_guidance", (
        r"\b(recover|restore|scan for|find)\b.{0,40}\b(drive|usb|disk|volume)\b",
        r"\b(drive recovery|recover the entire drive|recover the usb)\b",
    )),
    ("recovery_file_guidance", (
        r"\b(recover|restore|undelete|bring back)\b.{0,40}\b(file|folder|document|photo|pdf)\b",
        r"\b(file recovery|recover a file)\b",
    )),
    ("verification", (
        r"\b(verified|verification|prove|permanently gone|irrecoverable|irrecoverability)\b",
        r"\b(is my data gone|is it permanently deleted|does the certificate prove)\b",
    )),
    ("error", (
        r"\b(error|failed|failure|not working|could not|cannot|can't|why did .* fail)\b",
        r"\b(no physical extents|access denied|permission denied|timed out|interrupted)\b",
    )),
    ("scan_explanation", (
        r"\b(scan|scanned|deleted entries|deleted files|hidden files|scan results|what did it find)\b",
    )),
    ("device_info", (
        r"\b(device|drive|usb|pendrive|pen drive|capacity|filesystem|file system|connected)\b",
    )),
    ("ml_explanation", (
        r"\b(ml|machine learning|similarity score|recoverability|risk level|prediction|recommendation)\b",
    )),
    ("operation_status", (
        r"\b(status|progress|last operation|last wipe|what happened|operation result|result of the wipe)\b",
    )),
    ("recovery_guidance", (
        r"\b(recover|recovery|restore|undelete|bring back)\b",
    )),
    ("wipe_guidance", (
        r"\b(wipe|erasure|single pass|three pass|three-pass|7-pass|seven pass|dod)\b",
    )),
    ("navigation", (
        r"\b(open|go to|show me|take me to|navigate)\s+(the\s+)?(dashboard|devices|scan results|operations|activity log|history|certificates|settings|assistant)\b",
    )),
    ("greeting", (
        r"^(hi|hello|hey|good morning|good afternoon|good evening|thanks|thank you)[!. ]*$",
    )),
    ("help", (
        r"\b(help|what can you do|how do i use|how to use this app)\b",
    )),
)



def classify_intent(question: str) -> str:
    text = question.strip().lower()
    for intent, patterns in _PATTERNS:
        if any(re.search(pattern, text) for pattern in patterns):
            return intent
    return "unknown"
