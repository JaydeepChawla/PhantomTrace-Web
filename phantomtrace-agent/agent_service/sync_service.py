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
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from .config import DEFAULT_API_URL
from .auth import auth_manager
from .logging_service import logger

MAX_SYNC_RETRIES = 3
INITIAL_BACKOFF_SECONDS = 1.0

class CloudSyncService:
    def __init__(self, api_url: str = DEFAULT_API_URL):
        self.api_url = api_url.rstrip("/")

    def upload_scan(self, scan_path: Path) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Uploads a validated scan_results.json to the backend API.
        Enforces strict authentication boundaries, bounded retries for transient errors,
        and preservation of local scan results at all times.
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
            return False, msg, {"auth_blocked": True, "local_preserved": True}

        logger.info(f"[CloudSync] Initiating secure upload to {self.api_url}/api/scans/ingest")

        try:
            with open(scan_path, "rb") as f:
                payload = f.read()

            # Pre-validate payload structure locally before network transmission
            try:
                parsed_scan = json.loads(payload.decode("utf-8"))
                if not isinstance(parsed_scan, dict):
                    err_msg = "Scan payload invalid: Root must be a JSON object."
                    logger.error(f"[CloudSync] {err_msg}")
                    return False, err_msg, None
                processes_list = parsed_scan.get("processes") or parsed_scan.get("results")
                if not isinstance(processes_list, list):
                    err_msg = "Scan payload invalid: Missing 'processes' collection."
                    logger.error(f"[CloudSync] {err_msg}")
                    return False, err_msg, None
            except Exception as parse_err:
                err_msg = f"Scan payload is not valid JSON: {parse_err}"
                logger.error(f"[CloudSync] {err_msg}")
                return False, err_msg, None

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

            last_error_msg = ""
            for attempt in range(1, MAX_SYNC_RETRIES + 1):
                try:
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

                        # Verify server response payload has genuine confirmation
                        if status_code in (200, 201) and (res_data.get("scanId") or res_data.get("success")):
                            if res_data.get("duplicate"):
                                logger.info(
                                    f"[CloudSync] Duplicate scan verified (HTTP {status_code}). "
                                    f"Scan ID: {res_data.get('scanId')} reused idempotently."
                                )
                            else:
                                logger.info(
                                    f"[CloudSync] Ingestion successful (HTTP {status_code}). "
                                    f"Scan ID: {res_data.get('scanId')}"
                                )
                            return True, "Scan successfully synchronized to cloud.", res_data
                        else:
                            last_error_msg = f"Unexpected response from server (HTTP {status_code})"
                            logger.warning(f"[CloudSync] {last_error_msg}")

                except urllib.error.HTTPError as e:
                    # Permanent client errors (400, 401, 403, 404): DO NOT repeatedly retry
                    if e.code in (400, 401, 403, 404):
                        err_msg = f"Cloud upload rejected by server (HTTP {e.code}): {e.reason}"
                        try:
                            err_details = json.loads(e.read().decode("utf-8"))
                            if isinstance(err_details, dict):
                                server_detail = err_details.get("message") or err_details.get("error")
                                if server_detail and server_detail != e.reason:
                                    err_msg += f" - {server_detail}"
                        except Exception:
                            pass
                        logger.error(f"[CloudSync] Permanent authentication/request error: {err_msg}")
                        return False, err_msg, {"status_code": e.code, "permanent": True}

                    # Transient server errors (500, 502, 503, 504): Bounded retry
                    last_error_msg = f"Server transient error (HTTP {e.code}): {e.reason}"
                    logger.warning(f"[CloudSync] Attempt {attempt}/{MAX_SYNC_RETRIES} failed: {last_error_msg}")

                except urllib.error.URLError as e:
                    # Transient network error (offline, connection refused, DNS timeout)
                    last_error_msg = f"Network connection error: {e.reason}"
                    logger.warning(f"[CloudSync] Attempt {attempt}/{MAX_SYNC_RETRIES} failed: {last_error_msg}")

                except Exception as e:
                    last_error_msg = f"Unexpected error during sync attempt: {str(e)}"
                    logger.warning(f"[CloudSync] Attempt {attempt}/{MAX_SYNC_RETRIES} failed: {last_error_msg}")

                # If retries remaining, wait with exponential backoff
                if attempt < MAX_SYNC_RETRIES:
                    backoff = INITIAL_BACKOFF_SECONDS * (2 ** (attempt - 1))
                    logger.info(f"[CloudSync] Retrying upload in {backoff:.1f}s...")
                    time.sleep(backoff)

            # All retries exhausted
            final_msg = (
                f"Cloud synchronization failed after {MAX_SYNC_RETRIES} attempts: {last_error_msg}. "
                "Local scan results preserved on this device."
            )
            logger.error(f"[CloudSync] {final_msg}")
            return False, final_msg, {"retries_exhausted": True, "local_preserved": True}

        except Exception as outer_err:
            err_msg = f"Failed to prepare scan upload: {str(outer_err)}"
            logger.error(f"[CloudSync] {err_msg}")
            return False, err_msg, None

sync_service = CloudSyncService()
