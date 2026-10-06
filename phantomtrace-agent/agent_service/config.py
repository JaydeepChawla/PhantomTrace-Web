"""
=====================================================================
PHANTOMTRACE WINDOWS AGENT - CONFIGURATION
=====================================================================
Configuration management for the local PhantomTrace Windows Agent.
Binds strictly to localhost (127.0.0.1) for orchestration only.
ZERO detection code or memory tampering logic.
=====================================================================
"""

import os
import sys
from pathlib import Path

# Agent Version
AGENT_VERSION = "1.0.0"

# Localhost HTTP Server Configuration
# Strictly 127.0.0.1 - NEVER 0.0.0.0
HOST = "127.0.0.1"
PORT = int(os.environ.get("PHANTOMTRACE_AGENT_PORT", "49152"))

# Allowed Web Origins for CORS (Vercel Production & Local Development)
ALLOWED_ORIGINS = [
    "https://phantom-trace-web.vercel.app",
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]

# Cloud Backend API URL
DEFAULT_API_URL = os.environ.get(
    "PHANTOMTRACE_API_URL",
    "https://phantomtrace-web.onrender.com"
)

# Persistent Data Directory for Local Agent (Token, logs, scan metadata)
def get_data_dir() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data and sys.platform == "win32":
        path = Path(local_app_data) / "PhantomTraceAgent"
    else:
        path = Path.home() / ".phantomtrace_agent"
    path.mkdir(parents=True, exist_ok=True)
    return path

DATA_DIR = get_data_dir()
LOCAL_TOKEN_FILE = DATA_DIR / "local_token.json"
CLOUD_AUTH_FILE = DATA_DIR / "cloud_auth.json"
LOG_FILE = DATA_DIR / "phantomtrace_agent.log"
SCAN_OUTPUT_DIR = DATA_DIR / "scans"
SCAN_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Scanner Binary Candidates (Protected Stable Scanner)
def get_candidate_scanner_paths() -> list:
    paths = []
    # 1. Environment variable override
    if os.environ.get("PHANTOMTRACE_SCANNER_PATH"):
        paths.append(os.environ["PHANTOMTRACE_SCANNER_PATH"])

    # 2. Relative to sys.executable (packaged PyInstaller app)
    exe_dir = Path(sys.executable).resolve().parent
    paths.append(str(exe_dir / "scanner" / "PhantomTrace_Windows_Release_1.0.exe"))
    paths.append(str(exe_dir / "PhantomTrace_Windows_Release_1.0.exe"))
    paths.append(str(exe_dir.parent / "scanner" / "PhantomTrace_Windows_Release_1.0.exe"))

    # 3. Relative to current file (__file__)
    file_dir = Path(__file__).resolve().parent
    paths.append(str(file_dir.parent / "scanner" / "PhantomTrace_Windows_Release_1.0.exe"))
    paths.append(str(file_dir / "scanner" / "PhantomTrace_Windows_Release_1.0.exe"))
    paths.append(str(file_dir.parent.parent.parent.parent / "Phantom Trace" / "release" / "PhantomTrace_Windows_Release_1.0" / "PhantomTrace_Windows_Release_1.0.exe"))

    # 4. Canonical release directory on development host
    paths.append(r"D:\Phantom Trace\release\PhantomTrace_Windows_Release_1.0\PhantomTrace_Windows_Release_1.0.exe")
    return paths

def locate_scanner_executable() -> str:
    """Finds the existing, untouched PhantomTrace_Windows_Release_1.0.exe binary."""
    for candidate in get_candidate_scanner_paths():
        if candidate and os.path.isfile(candidate):
            return candidate
    return ""
