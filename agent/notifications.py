"""
PHANTOMTRACE WINDOWS NOTIFICATION SYSTEM — PHASE 2
=====================================================================
Windows-native notification system for PhantomTrace endpoint security.

CRITICAL ARCHITECTURAL & SECURITY CONSTRAINTS:
1. READ-ONLY: Does NOT modify, delete, quarantine, or terminate processes/files.
2. ZERO DATA HARVESTING: Does NOT read or transmit passwords, personal files, or file contents.
3. OFFLINE-FIRST: Operates 100% locally via Windows APIs; zero cloud dependency to notify.
4. NO PERSISTENCE: Does not install services or hidden startup tasks.
5. PRIVACY PRESERVED: Strips file paths, raw memory addresses, and sensitive arguments.
6. DEDUPLICATION: Prevents notification floods across scans and agent restarts.
7. SEVERITY-DRIVEN: Strictly follows existing PhantomTrace threat scores and levels.
=====================================================================
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# CONSTANTS & CONFIGURATION
# ============================================================

APP_NAME = "PhantomTrace Security"
DEFAULT_DASHBOARD_URL = "https://phantom-trace-web.vercel.app"
DEFAULT_COOLDOWN_SECONDS = 3600  # 1 hour suppression window for identical events
MAX_CACHE_ENTRIES = 500
MAX_AUDIT_LOG_ENTRIES = 1000

# Severity thresholds (aligned with agent/core/threat_score.py)
# NORMAL   : score <= 0     -> No notification
# LOW      : 0 < score < 25 -> No notification
# MEDIUM   : 25 <= score < 50 -> Notification when meaningful indicators exist
# HIGH     : 50 <= score < 75 -> Always notify
# CRITICAL : score >= 75     -> Always notify immediately


# ============================================================
# STORAGE DIRECTORIES
# ============================================================

def get_notification_dir() -> Path:
    """Returns persistent data directory for notification cache and audit logs."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data and sys.platform == "win32":
        path = Path(local_app_data) / "PhantomTraceAgent"
    else:
        path = Path.home() / ".phantomtrace_agent"

    try:
        path.mkdir(parents=True, exist_ok=True)
        return path
    except Exception:
        fallback = Path(".")
        return fallback


CACHE_FILE = get_notification_dir() / "notification_cache.json"
AUDIT_LOG_FILE = get_notification_dir() / "notification_audit.log"


# ============================================================
# EVENT IDENTIFIER & FINGERPRINTING
# ============================================================

def compute_event_id(alert: Dict[str, Any]) -> str:
    """
    Computes a stable, non-volatile fingerprint for a threat alert.
    Uses process basename, severity level, and sorted indicators.
    Does NOT depend on volatile PID to ensure scan-to-scan deduplication.
    """
    raw_name = str(alert.get("name") or "unknown").strip().lower()
    clean_name = Path(raw_name).name
    level = str(alert.get("level") or "NORMAL").strip().upper()

    indicators = alert.get("indicators", [])
    if isinstance(indicators, list):
        sorted_inds = sorted([str(i).strip() for i in indicators if i])
    else:
        sorted_inds = []

    fingerprint_raw = f"{clean_name}:{level}:{','.join(sorted_inds)}"
    return hashlib.sha256(fingerprint_raw.encode("utf-8")).hexdigest()[:16]


# ============================================================
# SEVERITY EVALUATION (STEP 4)
# ============================================================

def should_notify(alert: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Evaluates whether an alert meets the criteria for a Windows notification.
    Reuses the existing PhantomTrace threat scoring and severity system.
    """
    if not isinstance(alert, dict):
        return False, "Invalid alert object"

    level = str(alert.get("level") or "NORMAL").strip().upper()
    try:
        score = float(alert.get("score", 0.0) or 0.0)
    except (ValueError, TypeError):
        score = 0.0

    app_context = str(alert.get("application_context") or "STANDARD_PROCESS")
    memory_only = bool(alert.get("memory_only", False))
    has_behavior = bool(alert.get("has_behavior_evidence", False))

    # NORMAL: No threat
    if level == "NORMAL" or score <= 0:
        return False, "NORMAL threat level (score <= 0)"

    # LOW: Routine background or weak indicators
    if level == "LOW" or score < 25.0:
        return False, f"LOW threat level ({score:.1f} < 25.0)"

    # MEDIUM: 25.0 <= score < 50.0
    if level == "MEDIUM":
        # Suppress benign trusted common applications that only had memory anomalies
        if memory_only or (app_context == "TRUSTED_COMMON_APPLICATION" and not has_behavior):
            return False, "MEDIUM event in trusted application without behavioral evidence"

        # Check for meaningful indicators
        indicators = alert.get("indicators", [])
        if indicators or score >= 35.0 or has_behavior:
            return True, f"MEDIUM threat with active indicators (score: {score:.1f})"

        return False, "MEDIUM threat below notification criteria"

    # HIGH: 50.0 <= score < 75.0
    if level == "HIGH":
        return True, f"HIGH threat detected (score: {score:.1f})"

    # CRITICAL: score >= 75.0
    if level == "CRITICAL":
        return True, f"CRITICAL threat detected (score: {score:.1f})"

    return False, f"Unhandled threat level: {level}"


# ============================================================
# DEDUPLICATION MANAGER (STEP 5)
# ============================================================

class NotificationDeduplicator:
    """
    Manages persistent event deduplication to eliminate notification spam
    across successive scans and agent restarts.
    """

    def __init__(self, cache_path: Optional[Path] = None, cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS):
        self.cache_path = cache_path or CACHE_FILE
        self.cooldown_seconds = cooldown_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        if not self.cache_path.exists():
            self._cache = {}
            return

        try:
            with self.cache_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._cache = data
            else:
                self._cache = {}
        except Exception:
            self._cache = {}

    def _save_cache(self) -> None:
        try:
            # Maintain cache size limit
            if len(self._cache) > MAX_CACHE_ENTRIES:
                # Remove oldest entries based on last_notified
                sorted_keys = sorted(
                    self._cache.keys(),
                    key=lambda k: self._cache[k].get("last_notified", ""),
                )
                for k in sorted_keys[: len(self._cache) - MAX_CACHE_ENTRIES]:
                    del self._cache[k]

            with self.cache_path.open("w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def check_duplicate(self, event_id: str) -> Tuple[bool, str]:
        """
        Returns (is_duplicate, reason).
        If event was notified recently within the cooldown window, returns True.
        """
        if event_id not in self._cache:
            return False, "New event"

        entry = self._cache[event_id]
        last_str = entry.get("last_notified")
        if not last_str:
            return False, "New event record"

        try:
            last_time = datetime.fromisoformat(last_str).timestamp()
            elapsed = time.time() - last_time
            if elapsed < self.cooldown_seconds:
                remaining = int(self.cooldown_seconds - elapsed)
                return True, f"Duplicate event suppressed ({remaining}s remaining in cooldown)"
        except Exception:
            return False, "Timestamp parse error; allowing notification"

        return False, "Cooldown expired"

    def record_sent(self, event_id: str, alert: Dict[str, Any]) -> None:
        """Records a successful notification event in the persistent cache."""
        clean_name = Path(str(alert.get("name") or "unknown")).name
        current_entry = self._cache.get(event_id, {})
        count = int(current_entry.get("count", 0)) + 1

        self._cache[event_id] = {
            "last_notified": datetime.now().isoformat(),
            "process_name": clean_name,
            "level": str(alert.get("level") or "UNKNOWN").upper(),
            "score": float(alert.get("score", 0.0) or 0.0),
            "count": count,
        }
        self._save_cache()

    def clear(self) -> None:
        """Clears in-memory and on-disk deduplication cache."""
        self._cache = {}
        if self.cache_path.exists():
            try:
                self.cache_path.unlink()
            except Exception:
                pass


# ============================================================
# AUDIT LOGGING (STEP 7)
# ============================================================

def log_notification_audit(
    event_id: str,
    alert: Dict[str, Any],
    status: str,
    reason: str,
    mechanism: str = "N/A",
    audit_file: Optional[Path] = None,
) -> None:
    """
    Safely logs notification lifecycle events without exposing passwords,
    secrets, private keys, or raw file contents.
    """
    target_file = audit_file or AUDIT_LOG_FILE

    clean_name = Path(str(alert.get("name") or "unknown")).name
    level = str(alert.get("level") or "NORMAL").upper()
    try:
        score = round(float(alert.get("score", 0.0) or 0.0), 1)
    except Exception:
        score = 0.0

    entry = {
        "timestamp": datetime.now().isoformat(),
        "event_id": event_id,
        "process_name": clean_name,
        "level": level,
        "score": score,
        "status": status,  # "SENT" | "SUPPRESSED" | "IGNORED" | "FAILED"
        "reason": reason,
        "mechanism": mechanism,
    }

    try:
        with target_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


# ============================================================
# SANITIZATION & SAFE MESSAGE FORMATTING (STEP 9)
# ============================================================

def format_notification(alert: Dict[str, Any]) -> Dict[str, str]:
    """
    Generates a clean, professional, non-technical Windows notification payload.
    NEVER includes memory addresses, file contents, or raw paths.
    """
    raw_name = str(alert.get("name") or "Unknown Process").strip()
    safe_name = Path(raw_name).name  # Extract clean basename only

    level = str(alert.get("level") or "HIGH").strip().upper()
    try:
        score = float(alert.get("score", 0.0) or 0.0)
        score_str = f"{score:.1f}"
    except Exception:
        score_str = "N/A"

    if level == "CRITICAL":
        title = f"{APP_NAME}: Critical Threat Detected"
        body = f"High-risk suspicious activity detected on this PC ({safe_name}). Threat Score: {score_str}."
    elif level == "HIGH":
        title = f"{APP_NAME}: Suspicious Activity Detected"
        body = f"Potentially malicious activity detected ({safe_name}). Threat Score: {score_str}."
    else:
        title = f"{APP_NAME}: Security Notice"
        body = f"Potentially suspicious activity noted for {safe_name}. Threat Level: {level}."

    action_hint = "Open PhantomTrace for full investigation details."

    return {
        "app_name": APP_NAME,
        "title": title,
        "body": body,
        "details": action_hint,
        "process_name": safe_name,
        "level": level,
        "score": score_str,
        "launch_url": DEFAULT_DASHBOARD_URL,
    }


# ============================================================
# WINDOWS NATIVE DISPATCH ENGINE (STEP 3 & 6)
# ============================================================

def _dispatch_powershell_toast(payload: Dict[str, str]) -> bool:
    """
    Dispatches a native Windows 10/11 Toast Notification via PowerShell WinRT API.
    Offline-first: executes locally without network access.
    """
    if platform.system() != "Windows":
        return False

    title_safe = payload["title"].replace("'", "''").replace('"', '`"')
    body_safe = payload["body"].replace("'", "''").replace('"', '`"')
    details_safe = payload["details"].replace("'", "''").replace('"', '`"')
    launch_url = payload.get("launch_url", DEFAULT_DASHBOARD_URL).replace("'", "''")

    # PowerShell script using Windows.UI.Notifications WinRT toast manager
    # Includes activation launch URL so clicking the toast opens the dashboard (Step 10)
    ps_script = f"""
$ErrorActionPreference = 'Stop'
try {{
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

    $xmlString = @"
<toast activationType="protocol" launch="{launch_url}">
    <visual>
        <binding template="ToastGeneric">
            <text>{title_safe}</text>
            <text>{body_safe}</text>
            <text>{details_safe}</text>
        </binding>
    </visual>
    <actions>
        <action content="Open Dashboard" activationType="protocol" arguments="{launch_url}"/>
        <action content="Dismiss" activationType="system" arguments="dismiss"/>
    </actions>
</toast>
"@

    $xmlDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xmlDoc.LoadXml($xmlString)

    $appId = "PhantomTrace.Security"
    $toast = [Windows.UI.Notifications.ToastNotification]::new($xmlDoc)
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId)
    $notifier.Show($toast)
    exit 0
}} catch {{
    exit 1
}}
"""

    try:
        proc = subprocess.run(
            [
                "powershell.exe",
                "-ExecutionPolicy", "Bypass",
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle", "Hidden",
                "-Command", ps_script,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _dispatch_shell_notify_icon(payload: Dict[str, str]) -> bool:
    """
    Fallback native Win32 balloon notification using Shell_NotifyIconW via ctypes.
    Ensures notifications function even if PowerShell execution is locked down.
    """
    if platform.system() != "Windows":
        return False

    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8),
            ]

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("hWnd", wintypes.HWND),
                ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT),
                ("uCallbackMessage", wintypes.UINT),
                ("hIcon", wintypes.HICON),
                ("szTip", wintypes.WCHAR * 128),
                ("dwState", wintypes.DWORD),
                ("dwStateMask", wintypes.DWORD),
                ("szInfo", wintypes.WCHAR * 256),
                ("uTimeoutOrVersion", wintypes.UINT),
                ("szInfoTitle", wintypes.WCHAR * 64),
                ("dwInfoFlags", wintypes.DWORD),
                ("guidItem", GUID),
                ("hBalloonIcon", wintypes.HICON),
            ]

        NIF_INFO = 0x00000010
        NIF_TIP = 0x00000004
        NIIF_WARNING = 0x00000002
        NIIF_ERROR = 0x00000003
        NIM_ADD = 0x00000000
        NIM_DELETE = 0x00000002

        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = 0
        nid.uID = 1001
        nid.uFlags = NIF_INFO | NIF_TIP
        nid.szTip = APP_NAME[:127]
        nid.szInfoTitle = payload["title"][:63]
        nid.szInfo = payload["body"][:255]
        nid.dwInfoFlags = NIIF_ERROR if payload.get("level") == "CRITICAL" else NIIF_WARNING

        shell32 = ctypes.windll.shell32
        success = bool(shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)))
        if success:
            # Briefly allow message pump before cleanup
            time.sleep(0.5)
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
        return success
    except Exception:
        return False


# Global hook for test environments to intercept dispatched notifications
_test_notification_sink: Optional[List[Dict[str, Any]]] = None


def set_test_notification_sink(sink: Optional[List[Dict[str, Any]]]) -> None:
    """Configures an in-memory sink for automated unit testing."""
    global _test_notification_sink
    _test_notification_sink = sink


def send_windows_notification(payload: Dict[str, str]) -> Tuple[bool, str]:
    """
    Dispatches a native Windows notification.
    Tries PowerShell WinRT Toast -> falls back to Shell_NotifyIconW -> records to test sink.
    """
    global _test_notification_sink
    if _test_notification_sink is not None:
        _test_notification_sink.append(dict(payload))
        return True, "TEST_SINK"

    # Try PowerShell WinRT Toast
    if _dispatch_powershell_toast(payload):
        return True, "WINRT_TOAST"

    # Fallback to Shell_NotifyIconW
    if _dispatch_shell_notify_icon(payload):
        return True, "SHELL_NOTIFY_ICON"

    # Non-Windows or headless fallback
    return False, "DISPATCH_UNAVAILABLE"


# ============================================================
# MAIN ORCHESTRATION PIPELINE (STEP 2)
# ============================================================

def dispatch_threat_notifications(
    alerts: List[Dict[str, Any]],
    deduplicator: Optional[NotificationDeduplicator] = None,
    audit_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Main notification pipeline:
    Detection/Alerts
       ↓
    Severity Decision (should_notify)
       ↓
    Deduplication Check
       ↓
    Windows Native Notification
       ↓
    Safe Audit Logging
    """
    if not isinstance(alerts, list):
        return {"evaluated": 0, "sent": 0, "suppressed": 0, "ignored": 0}

    dedup = deduplicator or NotificationDeduplicator()

    metrics = {
        "evaluated": len(alerts),
        "sent": 0,
        "suppressed": 0,
        "ignored": 0,
        "dispatches": [],
    }

    for alert in alerts:
        if not isinstance(alert, dict):
            metrics["ignored"] += 1
            continue

        event_id = compute_event_id(alert)

        # 1. Severity check
        worthy, decision_reason = should_notify(alert)
        if not worthy:
            metrics["ignored"] += 1
            log_notification_audit(
                event_id=event_id,
                alert=alert,
                status="IGNORED",
                reason=decision_reason,
                audit_file=audit_file,
            )
            continue

        # 2. Deduplication check
        is_dup, dup_reason = dedup.check_duplicate(event_id)
        if is_dup:
            metrics["suppressed"] += 1
            log_notification_audit(
                event_id=event_id,
                alert=alert,
                status="SUPPRESSED",
                reason=dup_reason,
                audit_file=audit_file,
            )
            continue

        # 3. Format and dispatch notification
        payload = format_notification(alert)
        success, mechanism = send_windows_notification(payload)

        # 4. Record sent event
        dedup.record_sent(event_id, alert)
        status = "SENT" if success else "DISPATCH_ATTEMPTED"
        metrics["sent"] += 1
        metrics["dispatches"].append({
            "event_id": event_id,
            "process": payload["process_name"],
            "level": payload["level"],
            "mechanism": mechanism,
            "success": success,
        })

        log_notification_audit(
            event_id=event_id,
            alert=alert,
            status=status,
            reason=decision_reason,
            mechanism=mechanism,
            audit_file=audit_file,
        )

    return metrics
