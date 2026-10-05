"""
=====================================================================
PHANTOMTRACE WINDOWS AGENT - LOCALHOST REST API SERVER
=====================================================================
Lightweight local HTTP API listening strictly on 127.0.0.1.
Enables communication between the PhantomTrace web console and the
local Windows agent orchestration layer.

SECURITY GUARANTEES:
1. Binds ONLY to 127.0.0.1 (Loopback). Never exposed to LAN/WAN.
2. CORS restricted strictly to approved PhantomTrace web origins.
3. Private Network Access (PNA) preflight support for modern browsers.
4. ZERO arbitrary command execution endpoints (no shell, no powershell).
5. Only safe, explicit state queries and scan orchestration actions.
=====================================================================
"""

import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional
from .config import HOST, PORT, AGENT_VERSION, ALLOWED_ORIGINS, locate_scanner_executable
from .auth import auth_manager
from .scanner_launcher import ScannerLauncher, ScannerState
from .sync_service import sync_service
from .logging_service import logger

def _handle_scan_ready_for_upload(scan_file, summary):
    """Callback when scanner finishes generating scan_results.json."""
    logger.info(f"Scan ready for upload: {scan_file}")
    success, msg, data = sync_service.upload_scan(scan_file)
    launcher.set_upload_status(success, msg, data)

launcher = ScannerLauncher(on_scan_ready_for_upload=_handle_scan_ready_for_upload)

class LocalAgentRequestHandler(BaseHTTPRequestHandler):
    server_version = "PhantomTrace-Agent/1.0"

    def log_message(self, format, *args):
        # Route standard server logging through our logging service
        logger.debug(f"{self.address_string()} - {format % args}")

    def _get_cors_origin(self) -> Optional[str]:
        """Validates and returns allowed CORS origin."""
        origin = self.headers.get("Origin")
        if not origin:
            return "*"
        origin_clean = origin.rstrip("/")
        for allowed in ALLOWED_ORIGINS:
            if allowed.rstrip("/") == origin_clean:
                return origin
        # Allow localhost origins for local frontend testing
        if "localhost" in origin or "127.0.0.1" in origin:
            return origin
        return ALLOWED_ORIGINS[0]

    def _send_cors_headers(self):
        """Applies essential CORS and Private Network Access headers."""
        origin = self._get_cors_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Endpoint-Id, X-Local-Token")
        self.send_header("Access-Control-Allow-Credentials", "true")
        # Chrome/Chromium Private Network Access (PNA) header
        self.send_header("Access-Control-Allow-Private-Network", "true")

    def _send_json_response(self, status_code: int, data: dict):
        """Sends a JSON response with security and CORS headers."""
        try:
            body = json.dumps(data, indent=2).encode("utf-8")
            self.send_response(status_code)
            self._send_cors_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_OPTIONS(self):
        """Handle CORS and Private Network Access preflights."""
        self.send_response(204)
        self._send_cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        """Handle safe GET status queries."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path.rstrip("/")

        if path == "" or path == "/api" or path == "/api/status":
            scanner_exe = locate_scanner_executable()
            status_data = launcher.get_status()
            metadata = auth_manager.get_cloud_metadata()
            response = {
                "status": "ok",
                "agent": "PhantomTrace Windows Agent",
                "version": AGENT_VERSION,
                "connected": True,
                "scannerAvailable": bool(scanner_exe),
                "scannerPath": scanner_exe or "Not Found",
                "scanState": status_data.get("state", ScannerState.IDLE),
                "cloudAuthenticated": auth_manager.is_cloud_authenticated(),
                "deviceId": metadata.get("deviceId"),
                "deviceName": metadata.get("deviceName", "Windows PC"),
            }
            self._send_json_response(200, response)

        elif path == "/api/agent/info":
            scanner_exe = locate_scanner_executable()
            metadata = auth_manager.get_cloud_metadata()
            response = {
                "agentVersion": AGENT_VERSION,
                "platform": "Windows (x86_64)",
                "host": HOST,
                "port": PORT,
                "scannerPath": scanner_exe or "Not Found",
                "scannerAvailable": bool(scanner_exe),
                "cloudAuthenticated": auth_manager.is_cloud_authenticated(),
                "deviceId": metadata.get("deviceId"),
                "deviceName": metadata.get("deviceName", "Windows PC"),
                "readOnlyEnforced": True,
            }
            self._send_json_response(200, response)

        elif path == "/api/scan/status":
            status_data = launcher.get_status()
            self._send_json_response(200, status_data)

        else:
            self._send_json_response(404, {
                "error": "Not Found",
                "message": f"Endpoint '{path}' does not exist on local agent."
            })

    def do_POST(self):
        """Handle explicit scan triggers and device pairing."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path.rstrip("/")

        # Parse JSON body if present
        content_length = int(self.headers.get("Content-Length", 0))
        body_data = {}
        if content_length > 0:
            try:
                raw_body = self.rfile.read(content_length).decode("utf-8")
                body_data = json.loads(raw_body)
            except Exception:
                body_data = {}

        if path == "/api/scan/start":
            result = launcher.start_scan()
            status_code = 200 if result.get("success") else 409
            self._send_json_response(status_code, result)

        elif path == "/api/pair":
            # Device pairing endpoint: supports pairing code handshake or direct token
            pairing_code = body_data.get("pairingCode") or body_data.get("code")
            api_url = body_data.get("apiUrl")
            device_name = body_data.get("deviceName", "Windows PC")

            if pairing_code:
                # Execute full device pairing handshake with cloud server
                kwargs = {"pairing_code": pairing_code, "device_name": device_name}
                if api_url:
                    kwargs["api_url"] = api_url
                result = auth_manager.pair_device(**kwargs)
                status_code = 200 if result.get("success") else 400
                self._send_json_response(status_code, result)
                return

            token = body_data.get("token") or body_data.get("device_token")
            metadata = body_data.get("metadata", {})
            if not token:
                self._send_json_response(400, {
                    "error": "MissingCredentials",
                    "message": "Either pairingCode or device token is required."
                })
                return

            saved = auth_manager.set_cloud_credentials(token, metadata)
            if saved:
                self._send_json_response(200, {
                    "success": True,
                    "message": "Device successfully paired and authenticated for cloud sync."
                })
            else:
                self._send_json_response(500, {
                    "error": "StorageError",
                    "message": "Failed to persist device pairing token."
                })

        else:
            self._send_json_response(404, {
                "error": "Not Found",
                "message": f"POST endpoint '{path}' does not exist on local agent."
            })

def create_agent_server(host: str = HOST, port: int = PORT) -> HTTPServer:
    """Instantiates the HTTP server bound strictly to localhost."""
    server_address = (host, port)
    httpd = HTTPServer(server_address, LocalAgentRequestHandler)
    return httpd
