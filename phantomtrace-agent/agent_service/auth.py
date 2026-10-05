"""
=====================================================================
PHANTOMTRACE WINDOWS AGENT - AUTHENTICATION & PAIRING SERVICE
=====================================================================
Manages local pairing security and scoped cloud credentials.
NEVER contains hardcoded owner API keys or production database secrets.
=====================================================================
"""

import json
import secrets
import hmac
import os
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Dict, Any
from .config import LOCAL_TOKEN_FILE, CLOUD_AUTH_FILE, DEFAULT_API_URL
from .logging_service import logger

class AgentAuthManager:
    def __init__(self):
        self._local_token: str = ""
        self._cloud_token: Optional[str] = None
        self._cloud_metadata: Dict[str, Any] = {}
        self._init_local_token()
        self._load_cloud_credentials()

    def _init_local_token(self) -> None:
        """Loads existing local pairing token or generates a secure 32-byte hex token."""
        if LOCAL_TOKEN_FILE.exists():
            try:
                with open(LOCAL_TOKEN_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._local_token = data.get("local_token", "")
            except Exception as e:
                logger.warning(f"Could not read local token file: {e}")

        if not self._local_token:
            # Generate cryptographically secure random token for localhost pairing
            self._local_token = secrets.token_hex(32)
            try:
                with open(LOCAL_TOKEN_FILE, "w", encoding="utf-8") as f:
                    json.dump({"local_token": self._local_token}, f, indent=2)
                # Restrict permissions on Windows if possible
                try:
                    os.chmod(LOCAL_TOKEN_FILE, 0o600)
                except Exception:
                    pass
                logger.info(f"Initialized new local pairing token at {LOCAL_TOKEN_FILE}")
            except Exception as e:
                logger.error(f"Failed to persist local token: {e}")

    def _load_cloud_credentials(self) -> None:
        """Loads scoped device cloud credentials if enrolled."""
        if CLOUD_AUTH_FILE.exists():
            try:
                with open(CLOUD_AUTH_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._cloud_token = data.get("cloud_token")
                    self._cloud_metadata = data.get("metadata", {})
                    logger.info("Loaded enrolled cloud device credentials.")
            except Exception as e:
                logger.warning(f"Failed to read cloud auth file: {e}")
                self._cloud_token = None
        else:
            self._cloud_token = None
            self._cloud_metadata = {}

    def get_local_token(self) -> str:
        """Returns the local token for pairing with the website."""
        return self._local_token

    def validate_local_request(self, auth_header: Optional[str]) -> bool:
        """
        Validates request from localhost.
        Accepts Bearer token matching the local pairing token.
        For convenience during initial connection handshake on localhost,
        if header is omitted from same-origin localhost, it can be paired.
        """
        if not auth_header:
            return False

        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            # Constant-time comparison
            return hmac.compare_digest(token, self._local_token)

        return False

    def is_cloud_authenticated(self) -> bool:
        """Returns True if the agent possesses a valid cloud device credential."""
        return bool(self._cloud_token and len(self._cloud_token) > 0)

    def get_cloud_token(self) -> Optional[str]:
        """Returns the scoped cloud device credential for upload, if available."""
        return self._cloud_token

    def get_cloud_metadata(self) -> Dict[str, Any]:
        """Returns metadata about the paired device (deviceId, ownerUid)."""
        return self._cloud_metadata

    def set_cloud_credentials(self, token: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Saves enrolled device credentials issued by the server."""
        if not token or not token.strip():
            return False

        self._cloud_token = token.strip()
        self._cloud_metadata = metadata or {}

        try:
            with open(CLOUD_AUTH_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "cloud_token": self._cloud_token,
                    "metadata": self._cloud_metadata
                }, f, indent=2)
            try:
                os.chmod(CLOUD_AUTH_FILE, 0o600)
            except Exception:
                pass
            logger.info("Successfully updated cloud device credentials.")
            return True
        except Exception as e:
            logger.error(f"Failed to persist cloud credentials: {e}")
            return False

    def pair_device(
        self,
        pairing_code: str,
        api_url: str = DEFAULT_API_URL,
        device_name: str = "Windows PC",
        platform: str = "Windows 10/11 x86_64"
    ) -> Dict[str, Any]:
        """
        Completes device pairing with the cloud backend using a one-time pairing code.
        Stores the resulting device token safely in CLOUD_AUTH_FILE.
        """
        clean_code = pairing_code.strip().upper()
        if not clean_code:
            return {"success": False, "error": "Missing pairing code."}

        target_url = f"{api_url.rstrip('/')}/api/devices/pair/complete"
        payload = json.dumps({
            "pairingCode": clean_code,
            "deviceName": device_name,
            "platform": platform
        }).encode("utf-8")

        req = urllib.request.Request(
            url=target_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "PhantomTrace-Windows-Agent/1.0"
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                res_body = response.read().decode("utf-8")
                data = json.loads(res_body)

                device_token = data.get("deviceToken")
                device_id = data.get("deviceId")
                owner_uid = data.get("ownerUid")

                if not device_token or not device_id:
                    return {"success": False, "error": "Invalid server response during pairing."}

                self.set_cloud_credentials(device_token, {
                    "deviceId": device_id,
                    "ownerUid": owner_uid,
                    "deviceName": device_name,
                })

                logger.info(f"Successfully paired device '{device_id}' to user '{owner_uid}'.")
                return {
                    "success": True,
                    "deviceId": device_id,
                    "ownerUid": owner_uid,
                    "message": "Device paired successfully."
                }
        except urllib.error.HTTPError as e:
            err_msg = f"Pairing rejected (HTTP {e.code})"
            try:
                err_data = json.loads(e.read().decode("utf-8"))
                if isinstance(err_data, dict) and "message" in err_data:
                    err_msg = err_data["message"]
            except Exception:
                pass
            logger.error(f"Pairing error: {err_msg}")
            return {"success": False, "error": err_msg}
        except Exception as e:
            logger.error(f"Network error during pairing: {e}")
            return {"success": False, "error": f"Connection error: {str(e)}"}

auth_manager = AgentAuthManager()
