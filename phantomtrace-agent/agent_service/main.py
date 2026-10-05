"""
=====================================================================
PHANTOMTRACE WINDOWS AGENT - MAIN SERVICE ENTRYPOINT
=====================================================================
Starts the local PhantomTrace Windows Agent service.
Listens exclusively on 127.0.0.1 (localhost) to connect the
web dashboard with the existing Windows Release 1.0 scanner.
=====================================================================
"""

import sys
import signal
from .config import HOST, PORT, AGENT_VERSION, locate_scanner_executable, DATA_DIR
from .auth import auth_manager
from .local_api import create_agent_server
from .logging_service import logger

def print_banner():
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
    print(banner)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="PhantomTrace Windows Agent")
    parser.add_argument("--pair", help="One-time pairing code from the PhantomTrace dashboard (e.g. PT-7K4M-92QX)")
    parser.add_argument("--api-url", default=None, help="Custom cloud API URL")
    args = parser.parse_args()

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

    print_banner()

    server = create_agent_server(HOST, PORT)
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
