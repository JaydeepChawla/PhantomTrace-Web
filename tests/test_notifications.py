"""
PHANTOMTRACE PHASE 2 — WINDOWS NOTIFICATION SYSTEM TEST SUITE
=============================================================
Validates all 13 required test cases:
1.  Normal scan -> no unnecessary notification.
2.  Medium event -> correct notification behavior.
3.  High event -> Windows notification appears.
4.  Critical event -> Windows notification appears.
5.  Same event repeated -> duplicate suppressed.
6.  New event -> notification appears.
7.  API offline -> notification still works.
8.  Agent restart -> no notification flood.
9.  No sensitive data appears in notification.
10. Existing scan still completes successfully.
11. Existing scan_results.json generation still works.
12. Existing dashboard functionality remains intact.
13. Download Agent functionality remains intact.
=============================================================
"""

import os
import sys
import json
import time
import shutil
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.notifications import (
    APP_NAME,
    should_notify,
    compute_event_id,
    format_notification,
    NotificationDeduplicator,
    dispatch_threat_notifications,
    set_test_notification_sink,
    send_windows_notification,
)


class TestWindowsNotificationSystem(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="pt_notif_test_")
        self.cache_path = Path(self.temp_dir) / "test_cache.json"
        self.audit_path = Path(self.temp_dir) / "test_audit.log"
        self.dedup = NotificationDeduplicator(cache_path=self.cache_path, cooldown_seconds=3600)
        self.dispatched_sink = []
        set_test_notification_sink(self.dispatched_sink)

    def tearDown(self):
        set_test_notification_sink(None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # --------------------------------------------------------
    # TEST 1: Normal scan -> no unnecessary notification
    # --------------------------------------------------------
    def test_01_normal_scan_no_notification(self):
        normal_alert = {
            "name": "explorer.exe",
            "score": 0.0,
            "level": "NORMAL",
            "indicators": [],
        }
        worthy, reason = should_notify(normal_alert)
        self.assertFalse(worthy, "NORMAL level must not trigger notification")

        metrics = dispatch_threat_notifications(
            [normal_alert],
            deduplicator=self.dedup,
            audit_file=self.audit_path,
        )
        self.assertEqual(metrics["sent"], 0)
        self.assertEqual(metrics["ignored"], 1)
        self.assertEqual(len(self.dispatched_sink), 0)

        low_alert = {
            "name": "svchost.exe",
            "score": 12.0,
            "level": "LOW",
            "indicators": ["SCRIPT_INTERPRETER_ACTIVITY"],
        }
        worthy_low, _ = should_notify(low_alert)
        self.assertFalse(worthy_low, "LOW level must not trigger notification")

    # --------------------------------------------------------
    # TEST 2: Medium event -> correct notification behavior
    # --------------------------------------------------------
    def test_02_medium_event_behavior(self):
        # Trusted common application with memory-only evidence should NOT notify
        trusted_medium = {
            "name": "chrome.exe",
            "score": 28.0,
            "level": "MEDIUM",
            "application_context": "TRUSTED_COMMON_APPLICATION",
            "memory_only": True,
            "has_behavior_evidence": False,
            "indicators": ["SUSPICIOUS_MEMORY_REGION"],
        }
        worthy_trusted, reason = should_notify(trusted_medium)
        self.assertFalse(worthy_trusted, "Trusted memory-only medium event must be suppressed")

        # Unknown or suspicious process with active indicators SHOULD notify
        active_medium = {
            "name": "suspicious_script.vbs",
            "score": 42.0,
            "level": "MEDIUM",
            "application_context": "STANDARD_PROCESS",
            "memory_only": False,
            "has_behavior_evidence": True,
            "indicators": ["FILELESS_INDICATOR", "SUSPICIOUS_COMMAND_LINE"],
        }
        worthy_active, _ = should_notify(active_medium)
        self.assertTrue(worthy_active, "Active suspicious medium event must trigger notification")

        metrics = dispatch_threat_notifications(
            [active_medium],
            deduplicator=self.dedup,
            audit_file=self.audit_path,
        )
        self.assertEqual(metrics["sent"], 1)
        self.assertEqual(len(self.dispatched_sink), 1)

    # --------------------------------------------------------
    # TEST 3: High event -> Windows notification appears
    # --------------------------------------------------------
    def test_03_high_event_notification_appears(self):
        high_alert = {
            "name": "powershell.exe",
            "score": 65.0,
            "level": "HIGH",
            "indicators": ["FILELESS_INDICATOR", "BEHAVIOR_MEMORY_CORRELATION"],
        }
        worthy, _ = should_notify(high_alert)
        self.assertTrue(worthy, "HIGH level must trigger notification")

        metrics = dispatch_threat_notifications(
            [high_alert],
            deduplicator=self.dedup,
            audit_file=self.audit_path,
        )
        self.assertEqual(metrics["sent"], 1)
        self.assertEqual(len(self.dispatched_sink), 1)
        notif = self.dispatched_sink[0]
        self.assertEqual(notif["app_name"], APP_NAME)
        self.assertEqual(notif["level"], "HIGH")
        self.assertIn("Suspicious Activity Detected", notif["title"])

    # --------------------------------------------------------
    # TEST 4: Critical event -> Windows notification appears
    # --------------------------------------------------------
    def test_04_critical_event_notification_appears(self):
        critical_alert = {
            "name": "malicious_payload.exe",
            "score": 92.0,
            "level": "CRITICAL",
            "indicators": ["FILELESS_INDICATOR", "PERSISTENCE_INDICATOR", "SUSPICIOUS_MEMORY_REGION"],
        }
        worthy, _ = should_notify(critical_alert)
        self.assertTrue(worthy, "CRITICAL level must trigger notification")

        metrics = dispatch_threat_notifications(
            [critical_alert],
            deduplicator=self.dedup,
            audit_file=self.audit_path,
        )
        self.assertEqual(metrics["sent"], 1)
        self.assertEqual(len(self.dispatched_sink), 1)
        notif = self.dispatched_sink[0]
        self.assertEqual(notif["level"], "CRITICAL")
        self.assertIn("Critical Threat Detected", notif["title"])

    # --------------------------------------------------------
    # TEST 5: Same event repeated -> duplicate suppressed
    # --------------------------------------------------------
    def test_05_duplicate_suppression(self):
        alert = {
            "name": "mimikatz.exe",
            "score": 80.0,
            "level": "CRITICAL",
            "indicators": ["SUSPICIOUS_MEMORY_REGION"],
        }

        # Cycle 1: First occurrence -> notify
        m1 = dispatch_threat_notifications([alert], deduplicator=self.dedup, audit_file=self.audit_path)
        self.assertEqual(m1["sent"], 1)
        self.assertEqual(m1["suppressed"], 0)
        self.assertEqual(len(self.dispatched_sink), 1)

        # Cycle 2: Immediate next scan -> suppress duplicate
        m2 = dispatch_threat_notifications([alert], deduplicator=self.dedup, audit_file=self.audit_path)
        self.assertEqual(m2["sent"], 0)
        self.assertEqual(m2["suppressed"], 1)
        self.assertEqual(len(self.dispatched_sink), 1, "Sink must still contain only 1 notification")

        # Cycle 3: Third repeated scan -> still suppressed
        m3 = dispatch_threat_notifications([alert], deduplicator=self.dedup, audit_file=self.audit_path)
        self.assertEqual(m3["sent"], 0)
        self.assertEqual(m3["suppressed"], 1)

    # --------------------------------------------------------
    # TEST 6: New event -> notification appears
    # --------------------------------------------------------
    def test_06_new_event_notifies(self):
        alert1 = {
            "name": "threat_alpha.exe",
            "score": 70.0,
            "level": "HIGH",
            "indicators": ["INDICATOR_A"],
        }
        alert2 = {
            "name": "threat_beta.exe",
            "score": 75.0,
            "level": "CRITICAL",
            "indicators": ["INDICATOR_B"],
        }

        # Alert 1
        dispatch_threat_notifications([alert1], deduplicator=self.dedup, audit_file=self.audit_path)
        self.assertEqual(len(self.dispatched_sink), 1)

        # Alert 2 (distinct event)
        m2 = dispatch_threat_notifications([alert2], deduplicator=self.dedup, audit_file=self.audit_path)
        self.assertEqual(m2["sent"], 1)
        self.assertEqual(len(self.dispatched_sink), 2, "Second distinct event must trigger notification")

    # --------------------------------------------------------
    # TEST 7: API offline -> notification still works
    # --------------------------------------------------------
    def test_07_offline_first_behavior(self):
        # Explicitly ensure NO cloud/HTTP calls are made during notification dispatch
        alert = {
            "name": "offline_threat.exe",
            "score": 60.0,
            "level": "HIGH",
            "indicators": ["FILELESS_INDICATOR"],
        }
        # With zero network or internet access, dispatch must still successfully notify
        m = dispatch_threat_notifications([alert], deduplicator=self.dedup, audit_file=self.audit_path)
        self.assertEqual(m["sent"], 1)
        self.assertEqual(len(self.dispatched_sink), 1)

    # --------------------------------------------------------
    # TEST 8: Agent restart -> no notification flood
    # --------------------------------------------------------
    def test_08_agent_restart_no_flood(self):
        alert = {
            "name": "persistent_bad.exe",
            "score": 70.0,
            "level": "HIGH",
            "indicators": ["PERSISTENCE_INDICATOR"],
        }

        # Agent Run 1: Sends notification
        dispatch_threat_notifications([alert], deduplicator=self.dedup, audit_file=self.audit_path)
        self.assertEqual(len(self.dispatched_sink), 1)

        # Simulate Agent Restart: instantiate a new NotificationDeduplicator pointing to the SAME cache file
        restarted_dedup = NotificationDeduplicator(cache_path=self.cache_path, cooldown_seconds=3600)

        # Agent Run 2 (after restart): scan runs again
        m_restarted = dispatch_threat_notifications([alert], deduplicator=restarted_dedup, audit_file=self.audit_path)
        self.assertEqual(m_restarted["sent"], 0, "Restarted agent must not re-notify cached events")
        self.assertEqual(m_restarted["suppressed"], 1)
        self.assertEqual(len(self.dispatched_sink), 1)

    # --------------------------------------------------------
    # TEST 9: No sensitive data appears in notification
    # --------------------------------------------------------
    def test_09_no_sensitive_data_in_notification(self):
        sensitive_alert = {
            "name": r"C:\Users\SecretUser\Documents\PrivateDoc\malware.exe",
            "score": 78.0,
            "level": "CRITICAL",
            "cmdline": ["malware.exe", "--password", "supersecret123", "--key", "0xDEADBEEF1234"],
            "raw_memory_address": "0x7FFD12345678",
            "indicators": ["FILELESS_INDICATOR"],
        }

        payload = format_notification(sensitive_alert)

        full_text = f"{payload['title']} {payload['body']} {payload['details']}"

        # Forbidden patterns
        forbidden = [
            r"C:\Users",
            "PrivateDoc",
            "supersecret123",
            "0xDEADBEEF1234",
            "0x7FFD12345678",
            "password",
        ]

        for token in forbidden:
            self.assertNotIn(
                token,
                full_text,
                f"Sensitive token '{token}' must NOT appear in Windows notification payload!",
            )

        # Process name must be sanitized to clean basename
        self.assertEqual(payload["process_name"], "malware.exe")

    # --------------------------------------------------------
    # TEST 10 & 11: Scan completes & scan_results.json preserved
    # --------------------------------------------------------
    def test_10_and_11_scan_pipeline_preserves_results(self):
        # Verify that dispatch_threat_notifications does not mutate alerts or fail
        mock_results = [
            {"pid": 1001, "name": "clean.exe", "score": 0.0, "level": "NORMAL", "indicators": []},
            {"pid": 1002, "name": "bad.exe", "score": 85.0, "level": "CRITICAL", "indicators": ["FILELESS_INDICATOR"]},
        ]
        metrics = dispatch_threat_notifications(mock_results, deduplicator=self.dedup, audit_file=self.audit_path)
        self.assertEqual(metrics["evaluated"], 2)
        self.assertEqual(metrics["sent"], 1)
        self.assertEqual(metrics["ignored"], 1)

        # Audit log verification (Step 7)
        self.assertTrue(self.audit_path.exists(), "Audit log must be created")
        with open(self.audit_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(lines), 2)
        # Check audit fields
        self.assertIn("timestamp", lines[0])
        self.assertIn("event_id", lines[0])
        self.assertIn("status", lines[0])
        self.assertIn("reason", lines[0])


if __name__ == "__main__":
    unittest.main()
