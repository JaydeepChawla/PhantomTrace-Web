"""
PHANTOMTRACE PHASE 3 — WEB THREAT MONITOR & WINDOWS NOTIFICATION INTEGRATION
=============================================================================
Validates:
1. Web threat alerts formatting and sanitization.
2. Phase 2 Windows notification pipeline integration.
3. Severity filtering (Normal/Low ignored, High/Critical notify).
4. Cooldown and duplicate suppression for web threat events.
5. Audit logging without sensitive credentials or paths.
6. Local Agent request validation and unauthorized submission rejection.
=============================================================================
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

# pyrefly: ignore [missing-import]
from agent.notifications import (
    APP_NAME,
    should_notify,
    compute_event_id,
    format_notification,
    NotificationDeduplicator,
    dispatch_threat_notifications,
    set_test_notification_sink,
)
agent_dir = PROJECT_ROOT / "phantomtrace-agent"
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

# pyrefly: ignore [missing-import]
from agent_service.local_api import LocalAgentRequestHandler



class TestWebThreatMonitorIntegration(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="pt_web_threat_test_")
        self.cache_path = Path(self.temp_dir) / "test_cache.json"
        self.audit_path = Path(self.temp_dir) / "test_audit.log"
        self.dedup = NotificationDeduplicator(cache_path=self.cache_path, cooldown_seconds=3600)
        self.dispatched_sink = []
        set_test_notification_sink(self.dispatched_sink)

    def tearDown(self):
        set_test_notification_sink(None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # TEST 1: High-confidence malicious domain triggers Windows notification
    # -------------------------------------------------------------------------
    def test_01_malicious_domain_notification_trigger(self):
        alert = {
            "source": "browser",
            "domain": "phishing-bank-login.com",
            "name": "phishing-bank-login.com",
            "level": "HIGH",
            "score": 85.0,
            "classification": "PHISHING",
            "ruleId": "TI-RULE-7412",
            "indicators": ["WEB_THREAT", "PHISHING", "TI-RULE-7412"],
            "explanation": "Confirmed financial phishing site.",
        }

        worthy, reason = should_notify(alert)
        self.assertTrue(worthy, f"HIGH web threat must be worthy of notification: {reason}")

        payload = format_notification(alert)
        self.assertIn("phishing-bank-login.com", payload["body"])
        self.assertIn("Web Threat Detected", payload["title"])
        self.assertEqual(payload["level"], "HIGH")

        metrics = dispatch_threat_notifications(
            [alert],
            deduplicator=self.dedup,
            audit_file=self.audit_path,
        )
        self.assertEqual(metrics["sent"], 1)
        self.assertEqual(len(self.dispatched_sink), 1)
        self.assertEqual(self.dispatched_sink[0]["process_name"], "phishing-bank-login.com")

    # -------------------------------------------------------------------------
    # TEST 2: Critical malware distribution domain triggers Critical notification
    # -------------------------------------------------------------------------
    def test_02_critical_malware_notification_trigger(self):
        alert = {
            "source": "browser",
            "domain": "malware-drop-test.xyz",
            "level": "CRITICAL",
            "score": 95.0,
            "classification": "MALWARE",
            "ruleId": "TI-RULE-8801",
            "indicators": ["WEB_THREAT", "MALWARE"],
            "explanation": "Active second-stage malware distribution host.",
        }

        worthy, _ = should_notify(alert)
        self.assertTrue(worthy)

        payload = format_notification(alert)
        self.assertIn("Critical Web Threat Blocked", payload["title"])
        self.assertIn("malware-drop-test.xyz", payload["body"])

        metrics = dispatch_threat_notifications(
            [alert],
            deduplicator=self.dedup,
            audit_file=self.audit_path,
        )
        self.assertEqual(metrics["sent"], 1)

    # -------------------------------------------------------------------------
    # TEST 3: Duplicate threat event is suppressed within cooldown window
    # -------------------------------------------------------------------------
    def test_03_web_threat_duplicate_suppression(self):
        alert = {
            "source": "browser",
            "domain": "repeated-phishing-test.com",
            "level": "HIGH",
            "score": 80.0,
            "classification": "PHISHING",
            "indicators": ["WEB_THREAT", "PHISHING"],
        }

        # First dispatch -> SENT
        metrics1 = dispatch_threat_notifications(
            [alert],
            deduplicator=self.dedup,
            audit_file=self.audit_path,
        )
        self.assertEqual(metrics1["sent"], 1)
        self.assertEqual(metrics1["suppressed"], 0)

        # Immediate second dispatch -> SUPPRESSED
        metrics2 = dispatch_threat_notifications(
            [alert],
            deduplicator=self.dedup,
            audit_file=self.audit_path,
        )
        self.assertEqual(metrics2["sent"], 0)
        self.assertEqual(metrics2["suppressed"], 1)
        self.assertEqual(len(self.dispatched_sink), 1, "Only one physical notification allowed in cooldown")

    # -------------------------------------------------------------------------
    # TEST 4: Benign or low severity navigation does not produce notification
    # -------------------------------------------------------------------------
    def test_04_benign_navigation_no_notification(self):
        benign_alert = {
            "source": "browser",
            "domain": "google.com",
            "level": "NORMAL",
            "score": 0.0,
            "classification": "BENIGN",
        }

        worthy, _ = should_notify(benign_alert)
        self.assertFalse(worthy, "NORMAL web navigation must not trigger notification")

        metrics = dispatch_threat_notifications(
            [benign_alert],
            deduplicator=self.dedup,
            audit_file=self.audit_path,
        )
        self.assertEqual(metrics["sent"], 0)
        self.assertEqual(metrics["ignored"], 1)
        self.assertEqual(len(self.dispatched_sink), 0)

    # -------------------------------------------------------------------------
    # TEST 5: Privacy sanitization in notification and audit logging
    # -------------------------------------------------------------------------
    def test_05_privacy_preservation_no_credentials_or_query_params(self):
        alert = {
            "source": "browser",
            "domain": "phishing.com",
            "level": "HIGH",
            "score": 75.0,
            "classification": "PHISHING",
            # Ensure even if raw metadata contained private tokens, payload is safe
            "raw_url": "https://user:password123@phishing.com/login?token=secret#hash",
            "explanation": "Suspicious login interceptor.",
        }

        payload = format_notification(alert)
        payload_str = json.dumps(payload)
        self.assertNotIn("password123", payload_str)
        self.assertNotIn("token=secret", payload_str)

        dispatch_threat_notifications(
            [alert],
            deduplicator=self.dedup,
            audit_file=self.audit_path,
        )

        # Verify audit log does not leak sensitive information
        with open(self.audit_path, "r", encoding="utf-8") as f:
            audit_content = f.read()
        self.assertNotIn("password123", audit_content)
        self.assertNotIn("token=secret", audit_content)

    # -------------------------------------------------------------------------
    # TEST 6: Event ID stable computation for domain and rules
    # -------------------------------------------------------------------------
    def test_06_stable_event_id_fingerprinting(self):
        alert1 = {
            "source": "browser",
            "domain": "Test-Domain.COM",
            "level": "HIGH",
            "indicators": ["WEB_THREAT", "RULE_B", "RULE_A"],
        }
        alert2 = {
            "source": "browser",
            "domain": "test-domain.com",
            "level": "HIGH",
            "indicators": ["RULE_A", "WEB_THREAT", "RULE_B"],
        }
        id1 = compute_event_id(alert1)
        id2 = compute_event_id(alert2)
        self.assertEqual(id1, id2, "Event ID must be deterministic and insensitive to case and indicator order")

    # -------------------------------------------------------------------------
    # TEST 7: Local Agent origin validation rejects unauthorized origins (Step 4 & 15)
    # -------------------------------------------------------------------------
    def test_07_origin_validation_and_unauthorized_rejection(self):
        class DummyHandler:
            headers = {}
        
        handler = LocalAgentRequestHandler.__new__(LocalAgentRequestHandler)

        # 1. Untrusted third-party website origins must be rejected
        untrusted_origins = [
            "https://evil-attacker.com",
            "http://malicious-tracker.xyz",
            "https://phishing-spoof.org",
            "http://not-localhost.com:5173",
        ]
        for origin in untrusted_origins:
            # pyrefly: ignore [bad-assignment]
            handler.headers = {"Origin": origin}
            self.assertFalse(
                handler._is_origin_allowed(origin),
                f"Untrusted origin '{origin}' must NOT be allowed"
            )
            self.assertIsNone(
                handler._get_cors_origin(),
                f"Untrusted origin '{origin}' must return None for CORS origin"
            )

        # 2. Approved extension and local origins must be permitted
        trusted_origins = [
            "chrome-extension://abcdefghijklmnop",
            "edge-extension://xyz1234567890",
            "extension://browser-extension-id",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "https://phantom-trace-web.vercel.app",
        ]
        for origin in trusted_origins:
            # pyrefly: ignore [bad-assignment]
            handler.headers = {"Origin": origin}
            self.assertTrue(
                handler._is_origin_allowed(origin),
                f"Trusted origin '{origin}' must be allowed"
            )
            self.assertEqual(
                handler._get_cors_origin(),
                origin,
                f"Trusted origin '{origin}' must be returned for CORS headers"
            )

    # -------------------------------------------------------------------------
    # TEST 8: Local Agent HTTP endpoint /api/threats/browser-event end-to-end
    # -------------------------------------------------------------------------
    def test_08_browser_event_http_dispatch(self):
        import threading
        import urllib.request
        # pyrefly: ignore [missing-import]
        from agent_service.local_api import create_agent_server

        server = create_agent_server("127.0.0.1", 0)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            # 1. Authorized extension request
            url = f"http://127.0.0.1:{port}/api/threats/browser-event"
            unique_domain = f"phishing-bank-{int(time.time() * 1000)}.com"
            payload = json.dumps({
                "domain": unique_domain,
                "level": "HIGH",
                "score": 85.0,
                "classification": "PHISHING",
                "ruleId": "TI-RULE-7412",
                "explanation": "Confirmed financial phishing site."
            }).encode("utf-8")

            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Origin": "chrome-extension://abcdefghijklmnop"
                }
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(data.get("success"))
                self.assertTrue(data.get("dispatched"))

            # 2. Unauthorized origin request must be rejected with 403
            bad_req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Origin": "https://evil-attacker.com"
                }
            )
            try:
                urllib.request.urlopen(bad_req, timeout=5)
                self.fail("Request from unauthorized origin must be rejected with 403")
            # pyrefly: ignore [implicit-import]
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 403)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()

