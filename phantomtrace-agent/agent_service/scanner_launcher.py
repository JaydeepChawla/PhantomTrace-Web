"""
=====================================================================
PHANTOMTRACE WINDOWS AGENT - SCANNER LAUNCHER & ORCHESTRATION
=====================================================================
Manages the execution lifecycle of the existing PhantomTrace Windows
Scanner (PhantomTrace_Windows_Release_1.0.exe).

CRITICAL ARCHITECTURAL CONSTRAINTS:
1. DOES NOT contain detection logic or memory scanning code.
2. DOES NOT modify process memory, system files, or registry.
3. Spawns the existing stable scanner executable as a child process.
4. Monitors execution, parses scan_results.json, and triggers sync.
=====================================================================
"""

import os
import sys
import json
import time
import subprocess
import threading
from pathlib import Path
from typing import Optional, Dict, Any, Callable
from .config import locate_scanner_executable, SCAN_OUTPUT_DIR
from .logging_service import logger

class ScannerState:
    IDLE = "IDLE"
    STARTING = "STARTING"
    SCANNING = "SCANNING"
    VALIDATING = "VALIDATING"
    UPLOADING = "UPLOADING"
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"

class ScannerLauncher:
    def __init__(self, on_scan_ready_for_upload: Optional[Callable[[Path, Dict[str, Any]], None]] = None):
        self.state: str = ScannerState.IDLE
        self.message: str = "Scanner ready"
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.process: Optional[subprocess.Popen] = None
        self.lock = threading.Lock()
        self.latest_scan_summary: Optional[Dict[str, Any]] = None
        self.latest_scan_file: Optional[Path] = None
        self.upload_result: Optional[Dict[str, Any]] = None
        self.on_scan_ready_for_upload = on_scan_ready_for_upload

    def get_status(self) -> Dict[str, Any]:
        """Returns the current state and metrics of the scanner."""
        with self.lock:
            elapsed = time.time() - self.start_time if self.state in [
                ScannerState.STARTING, ScannerState.SCANNING, ScannerState.VALIDATING, ScannerState.UPLOADING
            ] else (self.end_time - self.start_time if self.start_time > 0 else 0.0)

            return {
                "state": self.state,
                "message": self.message,
                "elapsedSeconds": round(elapsed, 1),
                "scanSummary": self.latest_scan_summary,
                "uploadResult": self.upload_result,
            }

    def start_scan(self) -> Dict[str, Any]:
        """Triggers a new Windows endpoint scan."""
        with self.lock:
            if self.state in [ScannerState.STARTING, ScannerState.SCANNING, ScannerState.VALIDATING, ScannerState.UPLOADING]:
                return {
                    "success": False,
                    "error": "A scan is already in progress.",
                    "state": self.state
                }

            scanner_exe = locate_scanner_executable()
            if not scanner_exe or not os.path.isfile(scanner_exe):
                self.state = ScannerState.ERROR
                self.message = "PhantomTrace Windows Scanner binary not found."
                logger.error(f"Cannot start scan: binary not found at candidate paths.")
                return {
                    "success": False,
                    "error": self.message,
                    "state": self.state
                }

            self.state = ScannerState.STARTING
            self.message = "Initializing Windows Scanner..."
            self.start_time = time.time()
            self.end_time = 0.0
            self.latest_scan_summary = None
            self.latest_scan_file = None
            self.upload_result = None

            # Spawn scanner in background thread to prevent blocking
            thread = threading.Thread(
                target=self._run_scanner_thread,
                args=(scanner_exe,),
                daemon=True
            )
            thread.start()

            return {
                "success": True,
                "message": "Scan started successfully.",
                "state": self.state
            }

    def _run_scanner_thread(self, scanner_exe: str) -> None:
        """Executes the scanner subprocess and awaits completion."""
        try:
            logger.info("=" * 60)
            logger.info("ORCHESTRATING PHANTOMTRACE WINDOWS SCANNER EXECUTION")
            logger.info(f"Target Binary: {scanner_exe}")
            logger.info("=" * 60)

            # Scanner writes scan_results.json into its execution directory
            scanner_dir = Path(scanner_exe).resolve().parent

            with self.lock:
                self.state = ScannerState.SCANNING
                self.message = "Scanning running Windows processes and memory..."

            # Execute the existing, untouched Windows Release 1.0 EXE
            # Using creationflags to avoid popping an intrusive command window if desired
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

            from .config import DATA_DIR
            exec_dir = DATA_DIR if DATA_DIR.is_dir() else scanner_dir

            self.process = subprocess.Popen(
                [scanner_exe],
                cwd=str(exec_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creation_flags,
                text=True,
                encoding="utf-8",
                errors="replace"
            )

            stdout, stderr = self.process.communicate()
            exit_code = self.process.returncode

            logger.info(f"Scanner process finished with exit code {exit_code}")
            if stdout:
                logger.info(f"Scanner stdout tail: {stdout[-500:].strip()}")
            if stderr:
                logger.warning(f"Scanner stderr tail: {stderr[-500:].strip()}")

            with self.lock:
                self.state = ScannerState.VALIDATING
                self.message = "Validating scan results..."

            # Look for scan_results.json in DATA_DIR, then scanner directory, then current directory
            expected_json = exec_dir / "scan_results.json"
            if not expected_json.is_file():
                expected_json = scanner_dir / "scan_results.json"
            if not expected_json.is_file():
                expected_json = Path("scan_results.json").resolve()

            if not expected_json.is_file():
                with self.lock:
                    self.state = ScannerState.ERROR
                    self.message = "Scan completed, but scan_results.json was not generated."
                    self.end_time = time.time()
                logger.error("scan_results.json not found after execution.")
                return

            # Validate scan_results.json
            with open(expected_json, "r", encoding="utf-8") as f:
                scan_data = json.load(f)

            if not isinstance(scan_data, dict):
                raise ValueError("Root of scan_results.json must be a JSON object.")

            processes = scan_data.get("processes") or scan_data.get("results") or []
            if not isinstance(processes, list):
                raise ValueError("Missing 'processes' or 'results' array in scan_results.json.")

            # Compute summary
            total_processes = len(processes)
            alerts_count = len(scan_data.get("threat_alerts") or scan_data.get("alerts") or [])
            highest_score = scan_data.get("highest_score") or scan_data.get("highestThreatScore") or 0
            timestamp = scan_data.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S")

            summary = {
                "totalProcesses": total_processes,
                "threatCount": alerts_count,
                "highestScore": highest_score,
                "timestamp": timestamp,
                "fileSizeKb": round(expected_json.stat().st_size / 1024, 1),
            }

            with self.lock:
                self.latest_scan_summary = summary
                self.latest_scan_file = expected_json
                self.state = ScannerState.UPLOADING
                self.message = f"Scanned {total_processes} processes. Preparing cloud synchronization..."

            logger.info(f"Scan validated: {total_processes} processes, highest score {highest_score}")

            # Notify sync service
            if self.on_scan_ready_for_upload:
                self.on_scan_ready_for_upload(expected_json, summary)
            else:
                with self.lock:
                    self.state = ScannerState.COMPLETED
                    self.message = f"Scan complete ({total_processes} processes scanned)."
                    self.end_time = time.time()

        except Exception as e:
            logger.error(f"Error during scan orchestration: {e}")
            with self.lock:
                self.state = ScannerState.ERROR
                self.message = f"Scan could not be completed: {str(e)}"
                self.end_time = time.time()
        finally:
            self.process = None

    def set_upload_status(self, success: bool, message: str, upload_data: Optional[Dict[str, Any]] = None) -> None:
        """Called by sync service when upload completes or is blocked."""
        with self.lock:
            self.end_time = time.time()
            self.upload_result = {
                "success": success,
                "message": message,
                "data": upload_data
            }
            if success:
                self.state = ScannerState.COMPLETED
                self.message = "Scan complete and synchronized with cloud."
            else:
                # If upload failed due to auth blocker, preserve the completed scan
                if "authentication" in message.lower() or "auth" in message.lower() or "pairing" in message.lower():
                    self.state = ScannerState.COMPLETED
                    self.message = f"Scan complete. {message}"
                else:
                    self.state = ScannerState.ERROR
                    self.message = message
