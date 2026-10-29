"""Fixture-only tests for DataGuard assistant routing, context and safety."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
sys.path.insert(0, str(APP))

from context_builder import build_context
from controller import RequestError, handle_request
from intents import classify_intent
from response_validator import validate_response


class AssistantTests(unittest.TestCase):
    def request(self, question, context=None):
        return handle_request({
            "request_id": "test-001",
            "question": question,
            "context": context or {},
        })

    def test_scan_answers_use_supplied_counts(self):
        response = self.request("What does this scan mean?", {
            "screen": "scan_results",
            "scan_summary": {
                "existing_entries": 12,
                "potentially_deleted_entries": 3,
                "scan_status": "completed",
            },
        })
        self.assertIn("12 existing entries", response["answer"])
        self.assertIn("3 potentially deleted entries", response["answer"])
        self.assertIn("does not prove", response["answer"])
        self.assertEqual(response["source"], "rule_based")

    def test_missing_context_is_not_invented(self):
        response = self.request("What did the scan find?")
        self.assertIn("no current scan summary", response["answer"].lower())
        self.assertTrue(response["suggested_navigation"])

    def test_direct_wipe_request_is_guidance_only(self):
        response = self.request("Wipe this file now")
        self.assertTrue(response["requires_user_action"])
        self.assertTrue(any(
            item["destination"] == "operations"
            for item in response["suggested_navigation"]
        ))
        self.assertIn("cannot execute", response["answer"].lower())

    def test_no_physical_extents_has_safe_advice(self):
        response = self.request("Why did the wipe fail? No physical extents were found.")
        self.assertIn("physical", response["answer"].lower())
        self.assertTrue(response["caveats"])

    def test_ml_values_are_never_fabricated(self):
        response = self.request("What is the recoverability score?")
        self.assertIn("won't calculate or invent", response["answer"])
        self.assertNotIn("0.00%", response["answer"])

    def test_certificate_uses_supplied_metadata(self):
        response = self.request("Explain this certificate", {
            "screen": "certificates",
            "certificate": {
                "certificate_id": "DG-TEST-001",
                "timestamp": "01 Jan 2026, 09:30:00 AM IST",
                "user": "fixture-user",
                "file_name": "sample.txt",
                "status": "SUCCESS",
                "verification": "PASSED",
            },
        })
        self.assertIn("DG-TEST-001", response["answer"])
        self.assertIn("fixture-user", response["answer"])
        self.assertIn("Verification: PASSED", response["answer"])

    def test_context_drops_unknown_or_sensitive_fields(self):
        clean = build_context({
            "screen": "operations",
            "password": "never forward",
            "raw_file_contents": "secret-content",
            "device": {"display_name": "USB", "serial_number": "SERIAL"},
        })
        self.assertNotIn("password", json.dumps(clean))
        self.assertNotIn("never forward", json.dumps(clean))
        self.assertNotIn("raw_file_contents", json.dumps(clean))
        self.assertNotIn("secret-content", json.dumps(clean))
        self.assertNotIn("serial_number", json.dumps(clean))

    def test_navigation_allowlist_rejects_arbitrary_destination(self):
        response = validate_response({
            "answer": "help",
            "suggested_navigation": [
                {"label": "Operations", "destination": "operations"},
                {"label": "Run command", "destination": "os_command"},
            ],
        }, "req")
        self.assertEqual(
            [item["destination"] for item in response["suggested_navigation"]],
            ["operations"],
        )

    def test_unknown_question_is_honest(self):
        response = self.request("Tell me my private password")
        self.assertIn("don't have enough", response["answer"].lower())
        self.assertNotIn("password", response["answer"].lower())

    def test_input_validation(self):
        with self.assertRaises(RequestError):
            self.request(" ")
        with self.assertRaises(RequestError):
            self.request("x" * 2001)


    def test_certificate_questions_take_certificate_context(self):
        response = self.request("What does this certificate prove?", {
            "screen": "certificates",
            "certificate": {
                "certificate_id": "DG-CERT-7",
                "user": "fixture",
                "file_name": "sample.bin",
                "status": "SUCCESS",
                "verification": "PASSED",
            },
        })
        self.assertIn("DG-CERT-7", response["answer"])
        self.assertIn("application-reported details", response["answer"])
        self.assertTrue(any("not a universal guarantee" in item for item in response["caveats"]))

    def test_whole_drive_goal_routes_to_guidance_not_execution(self):
        response = self.request("I want to erase the entire USB drive")
        self.assertEqual(response["answer_type"], "operation_guidance")
        self.assertTrue(response["requires_user_action"])
        self.assertTrue(any(
            item["destination"] == "operations"
            for item in response["suggested_navigation"]
        ))
        self.assertIn("will not start", response["answer"].lower())

    def test_file_and_drive_recovery_are_distinguished(self):
        file_answer = self.request("How can I recover a file?")
        drive_answer = self.request("How can I recover a USB drive?")
        self.assertEqual(file_answer["answer_type"], "file_recovery_guidance")
        self.assertEqual(drive_answer["answer_type"], "drive_recovery_guidance")
        self.assertIn("different device", file_answer["answer"])
        self.assertIn("full-drive recovery workflow", drive_answer["answer"])

    def test_certificate_intent_precedes_generic_verification_intent(self):
        self.assertEqual(classify_intent("What does my certificate prove?"), "certificate")

    def test_history_question_uses_latest_activity_record(self):
        response = self.request("Which file did I just wipe?", {
            "screen": "assistant",
            "activity_records": [
                {
                    "timestamp": "30 Oct 2026, 03:40:00 AM IST",
                    "user": "fixture-user",
                    "file_name": "new_report.pdf",
                    "location": "Drive E: > Deleted Files > new_report.pdf",
                    "method": "Three passes (DoD)",
                    "status": "SUCCESS",
                    "outcome": "Wiped successfully (verified)",
                    "verification": "Verification successful",
                    "certificate_id": "DG-HISTORY-001",
                },
                {
                    "file_name": "older.bin",
                    "location": "Drive E: > Deleted Files > older.bin",
                    "method": "Single pass (zero fill)",
                    "status": "SUCCESS",
                    "outcome": "Wiped successfully",
                    "timestamp": "29 Oct 2026, 10:00:00 PM IST",
                },
            ],
        })
        self.assertEqual(response["answer_type"], "history_lookup")
        self.assertIn("new_report.pdf", response["answer"])
        self.assertIn("Wiped successfully (verified)", response["answer"])
        self.assertIn("DG-HISTORY-001", response["answer"])
        self.assertNotIn("older.bin", response["answer"])

    def test_history_question_can_match_a_named_file(self):
        response = self.request("What was the result for older.bin?", {
            "activity_records": [
                {"file_name": "new_report.pdf", "outcome": "Wiped successfully"},
                {"file_name": "older.bin", "outcome": "Wipe failed / not completed",
                 "error_message": "No physical extents were found."},
            ],
        })
        self.assertEqual(response["answer_type"], "history_lookup")
        self.assertIn("older.bin", response["answer"])
        self.assertIn("No physical extents", response["answer"])

    def test_scan_question_lists_actual_scan_entries(self):
        response = self.request("What files did the scan find?", {
            "scan_summary": {"existing_entries": 2, "potentially_deleted_entries": 1, "scan_status": "completed"},
            "scan_entries": [
                {"file_name": "notes.txt", "location": "Drive E: > Documents > notes.txt", "status": "Existing"},
                {"file_name": "deleted_photo.jpg", "location": "Drive E: > Deleted Files > deleted_photo.jpg", "status": "DELETED", "is_deleted": True},
            ],
        })
        self.assertEqual(response["answer_type"], "scan_explanation")
        self.assertIn("notes.txt", response["answer"])
        self.assertIn("deleted_photo.jpg", response["answer"])

    def test_legacy_ml_question_uses_saved_hover_tooltip_details(self):
        response = self.request("Explain the legacy result and hover details for old_file.pdf", {
            "activity_records": [{
                "file_name": "old_file.pdf",
                "ml_summary": "Legacy result — previous score is not valid",
                "ml_details": "Similarity score: 27.40%\nRecoverability score: 54.20%\nRisk level: MEDIUM\nRecommendation: DoD 3-Pass",
                "outcome": "Wiped successfully",
                "certificate_id": "DG-LEGACY-1",
            }],
        })
        self.assertEqual(response["answer_type"], "history_lookup")
        self.assertIn("Similarity score: 27.40%", response["answer"])
        self.assertIn("Recoverability score: 54.20%", response["answer"])
        self.assertIn("not a validated current evaluation", response["answer"])

    def test_ml_query_without_filename_reads_latest_saved_hover_details(self):
        response = self.request("Explain the latest ML results shown on hover", {
            "last_recorded_operation": {
                "file_name": "latest.bin",
                "ml_summary": "Legacy result — previous score is not valid",
                "ml_details": "Similarity score: 18.75%\nRecoverability score: 42.50%\nRisk level: MEDIUM\nRecommendation: DoD 3-Pass",
            },
            "activity_records": [{
                "file_name": "latest.bin",
                "ml_summary": "Legacy result — previous score is not valid",
                "ml_details": "Similarity score: 18.75%\nRecoverability score: 42.50%\nRisk level: MEDIUM\nRecommendation: DoD 3-Pass",
            }],
        })
        self.assertEqual(response["answer_type"], "ml_explanation")
        self.assertIn("Similarity score: 18.75%", response["answer"])
        self.assertIn("Recoverability score: 42.50%", response["answer"])
        self.assertIn("historical values", response["answer"])

    def test_previous_wipe_name_phrase_routes_to_activity_history(self):
        self.assertEqual(
            classify_intent("Name the previously wiped file name"),
            "history_lookup",
        )

    def test_multi_record_history_answer_uses_activity_log(self):
        response = self.request("List my recent wipes", {
            "activity_records": [
                {
                    "file_name": "first.txt",
                    "location": "Drive E: > Deleted Files > first.txt",
                    "outcome": "Wiped successfully (verified)",
                    "method": "Three passes (DoD)",
                    "timestamp": "30 Oct 2026, 03:40 AM IST",
                },
                {
                    "file_name": "second.bin",
                    "location": "Drive E: > Deleted Files > second.bin",
                    "outcome": "Wipe failed / not completed",
                    "method": "Single pass (zero fill)",
                    "timestamp": "29 Oct 2026, 10:00 PM IST",
                },
            ],
        })
        self.assertEqual(response["answer_type"], "history_lookup")
        self.assertIn("relevant and recent records supplied by activity log", response["answer"].lower())
        self.assertIn("first.txt", response["answer"])
        self.assertIn("second.bin", response["answer"])

    def test_account_question_uses_current_session_context(self):
        response = self.request("Who am I logged in as?", {
            "signed_in_user": "current-user",
            "settings": {"signed_in_user": "current-user", "persistence": "Local SQLite"},
        })
        self.assertEqual(response["answer_type"], "account_information")
        self.assertIn("current-user", response["answer"])
        self.assertIn("Local SQLite", response["answer"])

    def test_device_question_can_list_inventory(self):
        response = self.request("How many devices are connected?", {
            "devices": [
                {"display_name": "USB Drive E:", "drive_letter": "E:", "capacity_bytes": 16000000000, "connected": True},
                {"display_name": "USB Drive F:", "drive_letter": "F:", "capacity_bytes": 32000000000, "connected": True},
            ],
        })
        self.assertEqual(response["answer_type"], "device_inventory")
        self.assertIn("USB Drive E:", response["answer"])
        self.assertIn("USB Drive F:", response["answer"])

    def test_certificate_question_lists_recent_certificates_when_none_selected(self):
        response = self.request("Show my certificates", {
            "certificate_records": [
                {"certificate_id": "DG-C1", "file_name": "sample1.txt", "outcome": "Wiped successfully", "pdf_ready": True},
                {"certificate_id": "DG-C2", "file_name": "sample2.txt", "outcome": "Wipe failed", "pdf_ready": False},
            ],
        })
        self.assertEqual(response["answer_type"], "certificate_list")
        self.assertIn("DG-C1", response["answer"])
        self.assertIn("sample2.txt", response["answer"])
        self.assertIn("Relevant and recent certificate records", response["answer"])

    def test_extended_context_keeps_recent_records_and_scan_entries(self):
        clean = build_context({
            "screen": "assistant",
            "activity_records": [{"file_name": "recent.txt", "outcome": "Wiped successfully", "ml_details": "Similarity score: 20%", "raw_data": "do not pass"}],
            "certificate_records": [{"certificate_id": "DG-1", "pdf_ready": True}],
            "scan_entries": [{"file_name": "visible.txt", "location": "Drive E: > visible.txt", "status": "Existing"}],
            "devices": [{"display_name": "USB E:", "serial_number": "private-serial"}],
        })
        encoded = json.dumps(clean)
        self.assertIn("recent.txt", encoded)
        self.assertIn("Similarity score: 20%", encoded)
        self.assertIn("DG-1", encoded)
        self.assertIn("visible.txt", encoded)
        self.assertNotIn("do not pass", encoded)
        self.assertNotIn("private-serial", encoded)
        self.assertNotIn("serial_number", encoded)

    def test_process_protocol_emits_single_json_response(self):
        payload = json.dumps({
            "request_id": "subprocess-test",
            "question": "hello",
            "context": {},
        }).encode("utf-8")
        run = subprocess.run(
            [sys.executable, str(APP / "main.py")],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(ROOT),
            timeout=5,
            check=False,
        )
        self.assertEqual(run.returncode, 0, run.stderr.decode("utf-8", "replace"))
        decoded = json.loads(run.stdout.decode("utf-8"))
        self.assertEqual(decoded["request_id"], "subprocess-test")
        self.assertEqual(decoded["source"], "rule_based")


if __name__ == "__main__":
    unittest.main()
