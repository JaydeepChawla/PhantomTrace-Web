"""
=====================================================================
PHANTOMTRACE WINDOWS AGENT - CLOUD SYNCHRONIZATION SERVICE
=====================================================================
Handles authenticated transmission of scan_results.json to the
Render / PostgreSQL backend.

CRITICAL SECURITY RULES:
1. NEVER embeds or exposes the owner's PHANTOMTRACE_API_KEY.
2. NEVER transmits scans to unauthenticated endpoints.
3. If public user authentication or device pairing is missing,
   stops at the authentication boundary and preserves local data.
=====================================================================
"""

import json
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from .config import DEFAULT_API_URL
from .auth import auth_manager
from .logging_service import logger

class CloudSyncService:
    def __init__(self, api_url: str = DEFAULT_API_URL):
        self.api_url = api_url.rstrip("/")

    def upload_scan(self, scan_path: Path) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Uploads a validated scan_results.json to the backend API.
        Enforces strict authentication boundaries.
        """
        if not scan_path.is_file():
            return False, f"Scan file not found: {scan_path}", None

        # Check for cloud authentication
        cloud_token = auth_manager.get_cloud_token()
        if not cloud_token:
            msg = (
                "PUBLIC USER AUTHENTICATION IS THE REMAINING BLOCKER: "
                "Cloud synchronization requires device pairing credentials. "
                "Your scan was completed safely and remains stored locally on this PC."
            )
            logger.warning(f"[CloudSync] {msg}")
            return False, msg, {"auth_blocked": True}

        logger.info(f"[CloudSync] Initiating secure upload to {self.api_url}/api/scans/ingest")

        try:
            with open(scan_path, "rb") as f:
                payload = f.read()

            endpoint = f"{self.api_url}/api/scans/ingest"
            metadata = auth_manager.get_cloud_metadata()
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {cloud_token}",
                "User-Agent": "PhantomTrace-Windows-Agent/1.0",
            }
            if metadata.get("deviceId"):
                headers["X-Endpoint-Id"] = metadata["deviceId"]
                headers["X-Device-Id"] = metadata["deviceId"]

            req = urllib.request.Request(
                url=endpoint,
                data=payload,
                headers=headers,
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                status_code = response.getcode()
                response_body = response.read().decode("utf-8")
                res_data = json.loads(response_body)

                logger.info(f"[CloudSync] Ingestion successful (HTTP {status_code}). Scan ID: {res_data.get('scanId')}")
                return True, "Scan successfully synchronized to cloud.", res_data

        except urllib.error.HTTPError as e:
            err_msg = f"Cloud upload rejected by server (HTTP {e.code}): {e.reason}"
            try:
                err_details = json.loads(e.read().decode("utf-8"))
                if isinstance(err_details, dict) and "error" in err_details:
                    err_msg += f" - {err_details['error']}"
            except Exception:
                pass
            logger.error(f"[CloudSync] {err_msg}")
            return False, err_msg, None

        except urllib.error.URLError as e:
            err_msg = f"Network connection error while contacting cloud: {e.reason}"
            logger.error(f"[CloudSync] {err_msg}")
            return False, err_msg, None

        except Exception as e:
            err_msg = f"Unexpected error during cloud upload: {str(e)}"
            logger.error(f"[CloudSync] {err_msg}")
            return False, err_msg, None

sync_service = CloudSyncService()
