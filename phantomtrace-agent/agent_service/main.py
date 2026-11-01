"""
=====================================================================
PHANTOMTRACE WINDOWS AGENT - MAIN SERVICE ENTRYPOINT
=====================================================================
Starts the local PhantomTrace Windows Agent service.
Listens exclusively on 127.0.0.1 (localhost) to connect the
web dashboard with the existing Windows Release 1.0 scanner.
=====================================================================
"""

import os
import sys
import signal
from .config import HOST, PORT, AGENT_VERSION, locate_scanner_executable, DATA_DIR
from .auth import auth_manager
from .local_api import create_agent_server
from .logging_service import logger
from .autostart import (
    enable_autostart,
    disable_autostart,
    is_autostart_enabled,
    get_autostart_info,
)

_single_instance_mutex = None

def attach_parent_console():
    """Attach to caller's console if executed from CMD/PowerShell so CLI output displays."""
    if sys.platform == "win32":
        try:
            import ctypes
            # 0xFFFFFFFF = ATTACH_PARENT_PROCESS
            if ctypes.windll.kernel32.AttachConsole(0xFFFFFFFF):
                sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace")
                sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace")
        except Exception:
            pass

def acquire_single_instance_mutex(name: str = "Local\\PhantomTraceAgentSingleInstanceMutex") -> bool:
    """Guarantees only one instance of PhantomTrace Agent runs at a time."""
    global _single_instance_mutex
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        ERROR_ALREADY_EXISTS = 183
        kernel32 = ctypes.windll.kernel32
        _single_instance_mutex = kernel32.CreateMutexW(None, True, name)
        last_error = kernel32.GetLastError()
        if last_error == ERROR_ALREADY_EXISTS:
            return False
        return bool(_single_instance_mutex)
    except Exception:
        return True

def stop_agent() -> int:
    """Stops running PhantomTrace Agent instance(s)."""
    current_pid = os.getpid()
    logger.info("Stop command received. Terminating existing PhantomTrace Agent instance(s)...")
    if sys.platform == "win32":
        try:
            import subprocess
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            subprocess.run(["taskkill.exe", "/F", "/FI", f"PID ne {current_pid}", "/IM", "PhantomTraceAgent.exe"], capture_output=True, creationflags=flags)
            subprocess.run(["taskkill.exe", "/F", "/FI", f"PID ne {current_pid}", "/IM", "PhantomTrace-Agent.exe"], capture_output=True, creationflags=flags)
        except Exception as e:
            logger.warning(f"Could not terminate agent process: {e}")

    msg = "PhantomTrace Agent stopped successfully."
    logger.info(msg)
    if sys.stdout is not None:
        try:
            print(msg)
        except Exception:
            pass
    return 0

def check_status() -> int:
    """Checks if the local PhantomTrace Agent service is running and healthy."""
    import urllib.request
    import json
    try:
        req = urllib.request.Request(f"http://{HOST}:{PORT}/api/status")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                scanner_state = data.get("scanner", {}).get("state", "UNKNOWN")
                cloud_enrolled = data.get("cloudEnrolled", False)
                msg = f"[RUNNING] PhantomTrace Agent is active on http://{HOST}:{PORT} (Scanner: {scanner_state}, Cloud Enrolled: {cloud_enrolled})"
                logger.info(msg)
                if sys.stdout is not None:
                    try:
                        print(msg)
                    except Exception:
                        pass
                return 0
    except Exception:
        pass
    msg = f"[STOPPED] PhantomTrace Agent service is not running on http://{HOST}:{PORT}."
    logger.info(msg)
    if sys.stdout is not None:
        try:
            print(msg)
        except Exception:
            pass
    return 1

def log_banner():
    scanner_path = locate_scanner_executable()
    banner = f"""
=====================================================================
  PHANTOMTRACE WINDOWS AGENT v{AGENT_VERSION}
  Real Endpoint Scanning & Cloud Sync Orchestration
=====================================================================
  Binding:        http://{HOST}:{PORT} (Localhost Only)
  Data Directory: {DATA_DIR}
  Scanner Path:   {scanner_path or "NOT FOUND"}
  Cloud Enrolled: {auth_manager.is_cloud_authenticated()}
  Security Model: 100% Read-Only Passive Inspection
=====================================================================
"""
    logger.info(banner.strip())
    if sys.stdout is not None:
        try:
            print(banner)
        except Exception:
            pass

def main():
    import argparse
    attach_parent_console()

    parser = argparse.ArgumentParser(description="PhantomTrace Windows Agent")
    parser.add_argument("--pair", help="One-time pairing code from the PhantomTrace dashboard (e.g. PT-7K4M-92QX)")
    parser.add_argument("--api-url", default=None, help="Custom cloud API URL")
    parser.add_argument("--stop", action="store_true", help="Stop running PhantomTrace Agent service")
    parser.add_argument("--status", action="store_true", help="Check status of PhantomTrace Agent service")
    parser.add_argument("--enable-autostart", action="store_true", help="Enable automatic agent startup on Windows logon (Opt-in)")
    parser.add_argument("--disable-autostart", action="store_true", help="Disable automatic agent startup on Windows logon")
    parser.add_argument("--autostart-status", action="store_true", help="Display current automatic startup configuration")
    args = parser.parse_args()

    if args.stop:
        sys.exit(stop_agent())

    if args.status:
        sys.exit(check_status())

    if args.autostart_status:
        info = get_autostart_info()
        print(f"[AUTOSTART STATUS] {info['status'].upper()}: {info['message']}")
        sys.exit(0)

    if args.enable_autostart:
        success, msg = enable_autostart()
        print(f"[{'PASS' if success else 'FAIL'}] {msg}")
        sys.exit(0 if success else 1)

    if args.disable_autostart:
        success, msg = disable_autostart()
        print(f"[{'PASS' if success else 'FAIL'}] {msg}")
        sys.exit(0 if success else 1)

    if args.pair:
        print("=" * 60)
        print("  PHANTOMTRACE WINDOWS AGENT - DEVICE PAIRING")
        print("=" * 60)
        print(f"Connecting to account with pairing code: {args.pair}...")
        kwargs = {"pairing_code": args.pair}
        if args.api_url:
            kwargs["api_url"] = args.api_url
        result = auth_manager.pair_device(**kwargs)
        if result.get("success"):
            print(f"[PASS] ✓ PC Connected! Device ID: {result.get('deviceId')}")
            print("       Your Windows PC is now enrolled. Scans will sync automatically.")
            sys.exit(0)
        else:
            print(f"[FAIL] Pairing failed: {result.get('error')}")
            sys.exit(1)

    if not acquire_single_instance_mutex():
        logger.info(f"Another instance of PhantomTrace Agent is already running on localhost:{PORT}. Exiting duplicate process.")
        sys.exit(0)

    log_banner()

    try:
        server = create_agent_server(HOST, PORT)
    except OSError as e:
        logger.warning(f"Could not bind PhantomTrace Agent server on {HOST}:{PORT}: {e}. Another process is already listening.")
        sys.exit(0)

    logger.info(f"PhantomTrace Agent service started successfully on http://{HOST}:{PORT}")

    def handle_exit(signum, frame):
        logger.info("Shutdown signal received. Stopping PhantomTrace Agent...")
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        logger.info("PhantomTrace Agent stopped.")

if __name__ == "__main__":
    main()
