"""
=====================================================================
PHANTOMTRACE WINDOWS AGENT - LOGGING SERVICE
=====================================================================
Structured, privacy-preserving logging for the local Windows Agent.
Does NOT log secrets, tokens, or raw endpoint memory telemetry.
=====================================================================
"""

import logging
import sys
from .config import LOG_FILE

def setup_logger(name: str = "PhantomTraceAgent") -> logging.Logger:
    """Configures structured console and file logging."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console Handler (stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File Handler
    try:
        file_handler = logging.FileHandler(str(LOG_FILE), encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        sys.stderr.write(f"Warning: Could not initialize log file at {LOG_FILE}: {e}\n")

    return logger

logger = setup_logger()
