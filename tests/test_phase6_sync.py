"""
=====================================================================
PHANTOMTRACE PHASE 6: WINDOWS AGENT CLOUD SYNCHRONIZATION TESTS
=====================================================================
Unit tests verifying:
1. upload_scan bounded retries on transient errors
2. upload_scan fast-fail on permanent 401/403/400 errors
3. Offline local data preservation
4. Payload format validation
5. Verification of server response
=====================================================================
"""

import unittest
import sys
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import urllib.error

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "phantomtrace-agent") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "phantomtrace-agent"))

from agent_service.sync_service import CloudSyncService, MAX_SYNC_RETRIES
from agent_service.auth import auth_manager

class TestPhase6CloudSync(unittest.TestCase):
    def setUp(self):
        self.service = CloudSyncService("http://127.0.0.1:5000")
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scan_file = Path(self.temp_dir.name) / "scan_results.json"
        self.valid_payload = {
            "scan_id": "scan-unit-test-01",
            "timestamp": "2026-10-10T12:00:00Z",
            "processes": [
                {"pid": 1234, "name": "explorer.exe", "threat_score": 10}
            ]
        }
        with open(self.scan_file, "w", encoding="utf-8") as f:
            json.dump(self.valid_payload, f)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_missing_scan_file(self):
        non_existent = Path(self.temp_dir.name) / "does_not_exist.json"
        success, msg, data = self.service.upload_scan(non_existent)
        self.assertFalse(success)
        self.assertIn("not found", msg.lower())
        self.assertIsNone(data)

    def test_missing_cloud_token_stops_at_boundary_and_preserves_local_data(self):
        with patch.object(auth_manager, "get_cloud_token", return_value=None):
            success, msg, data = self.service.upload_scan(self.scan_file)
            self.assertFalse(success)
            self.assertIn("PUBLIC USER AUTHENTICATION IS THE REMAINING BLOCKER", msg)
            assert data is not None
            self.assertTrue(data.get("auth_blocked"))
            self.assertTrue(data.get("local_preserved"))
            # Local scan file still exists untouched
            self.assertTrue(self.scan_file.is_file())

    def test_invalid_json_payload_rejected_locally(self):
        bad_file = Path(self.temp_dir.name) / "corrupt.json"
        with open(bad_file, "w", encoding="utf-8") as f:
            f.write("{invalid-json-content")

        with patch.object(auth_manager, "get_cloud_token", return_value="pt_dev_valid_token"):
            success, msg, _ = self.service.upload_scan(bad_file)
            self.assertFalse(success)
            self.assertIn("valid json", msg.lower())

    def test_payload_missing_processes_rejected_locally(self):
        missing_proc_file = Path(self.temp_dir.name) / "no_proc.json"
        with open(missing_proc_file, "w", encoding="utf-8") as f:
            json.dump({"scan_id": "test", "other": 123}, f)

        with patch.object(auth_manager, "get_cloud_token", return_value="pt_dev_valid_token"):
            success, msg, _ = self.service.upload_scan(missing_proc_file)
            self.assertFalse(success)
            self.assertIn("processes", msg.lower())

    @patch("agent_service.sync_service.time.sleep")
    @patch("urllib.request.urlopen")
    def test_permanent_401_fast_fails_without_retrying(self, mock_urlopen, mock_sleep):
        # HTTP 401 Unauthorized
        fp = MagicMock()
        fp.read.return_value = b'{"error":"Unauthorized","message":"Invalid token"}'
        # pyrefly: ignore [bad-argument-type]
        err = urllib.error.HTTPError("http://127.0.0.1:5000", 401, "Unauthorized", {}, fp)
        mock_urlopen.side_effect = err

        with patch.object(auth_manager, "get_cloud_token", return_value="pt_dev_expired"):
            success, msg, data = self.service.upload_scan(self.scan_file)
            self.assertFalse(success)
            self.assertIn("401", msg)
            assert data is not None
            self.assertTrue(data.get("permanent"))
            # Fast fail: urlopen called only ONCE, sleep called 0 times
            self.assertEqual(mock_urlopen.call_count, 1)
            mock_sleep.assert_not_called()

    @patch("agent_service.sync_service.time.sleep")
    @patch("urllib.request.urlopen")
    def test_permanent_403_fast_fails_without_retrying(self, mock_urlopen, mock_sleep):
        fp = MagicMock()
        fp.read.return_value = b'{"error":"Forbidden","message":"Device revoked"}'
        # pyrefly: ignore [bad-argument-type]
        err = urllib.error.HTTPError("http://127.0.0.1:5000", 403, "Forbidden", {}, fp)
        mock_urlopen.side_effect = err

        with patch.object(auth_manager, "get_cloud_token", return_value="pt_dev_revoked"):
            success, msg, data = self.service.upload_scan(self.scan_file)
            self.assertFalse(success)
            self.assertIn("403", msg)
            assert data is not None
            self.assertTrue(data.get("permanent"))
            self.assertEqual(mock_urlopen.call_count, 1)
            mock_sleep.assert_not_called()

    @patch("agent_service.sync_service.time.sleep")
    @patch("urllib.request.urlopen")
    def test_transient_502_retries_bounded(self, mock_urlopen, mock_sleep):
        # HTTP 502 Bad Gateway
        fp = MagicMock()
        fp.read.return_value = b'{"error":"Bad Gateway"}'
        # pyrefly: ignore [bad-argument-type]
        err = urllib.error.HTTPError("http://127.0.0.1:5000", 502, "Bad Gateway", {}, fp)
        mock_urlopen.side_effect = err

        with patch.object(auth_manager, "get_cloud_token", return_value="pt_dev_valid"):
            success, msg, data = self.service.upload_scan(self.scan_file)
            self.assertFalse(success)
            # Reached MAX_SYNC_RETRIES attempts
            self.assertEqual(mock_urlopen.call_count, MAX_SYNC_RETRIES)
            self.assertEqual(mock_sleep.call_count, MAX_SYNC_RETRIES - 1)
            assert data is not None
            self.assertTrue(data.get("retries_exhausted"))
            self.assertTrue(data.get("local_preserved"))
            self.assertTrue(self.scan_file.is_file())

    @patch("agent_service.sync_service.time.sleep")
    @patch("urllib.request.urlopen")
    def test_transient_network_error_retries_then_succeeds(self, mock_urlopen, mock_sleep):
        # First attempt: connection error; Second attempt: success 201
        success_response = MagicMock()
        success_response.getcode.return_value = 201
        success_response.read.return_value = json.dumps({
            "success": True,
            "scanId": "scan-unit-test-01",
            "processesImported": 1
        }).encode("utf-8")
        success_response.__enter__.return_value = success_response
        success_response.__exit__.return_value = None

        net_err = urllib.error.URLError("Connection refused")
        mock_urlopen.side_effect = [net_err, success_response]

        with patch.object(auth_manager, "get_cloud_token", return_value="pt_dev_valid"):
            success, msg, data = self.service.upload_scan(self.scan_file)
            self.assertTrue(success)
            self.assertEqual(mock_urlopen.call_count, 2)
            self.assertEqual(mock_sleep.call_count, 1)
            assert data is not None
            self.assertEqual(data.get("scanId"), "scan-unit-test-01")

if __name__ == "__main__":
    unittest.main()
