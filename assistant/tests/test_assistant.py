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
from intents import classify_intent


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
