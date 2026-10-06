"""
=====================================================================
PHANTOMTRACE WINDOWS AGENT - RUNTIME ENTRYPOINT
=====================================================================
Direct executable entrypoint for PyInstaller packaging.
Orchestrates localhost service without requiring Python or pip.
=====================================================================
"""
import sys
import os

# Ensure package is resolvable regardless of frozen / dev execution
if getattr(sys, "frozen", False):
    base_dir = os.path.dirname(sys.executable)
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))

if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

from agent_service.main import main

if __name__ == "__main__":
    main()
