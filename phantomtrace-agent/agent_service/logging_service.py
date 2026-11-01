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

class SafeStreamWrapper:
    """Safe stream wrapper that captures writes to structured logs in windowless mode."""
    def __init__(self, target_logger: logging.Logger, level: int):
        self.target_logger = target_logger
        self.level = level
        self._buffer = ""

    def write(self, message: str):
        if not message:
            return
        self._buffer += message
        if "\n" in self._buffer or "\r" in self._buffer:
            lines = self._buffer.splitlines(keepends=True)
            self._buffer = ""
            for line in lines:
                if line.endswith("\n") or line.endswith("\r"):
                    stripped = line.strip()
                    if stripped:
                        self.target_logger.log(self.level, stripped)
                else:
                    self._buffer = line

    def flush(self):
        if self._buffer:
            stripped = self._buffer.strip()
            if stripped:
                self.target_logger.log(self.level, stripped)
            self._buffer = ""

    def isatty(self) -> bool:
        return False

def install_exception_hook(target_logger: logging.Logger):
    """Ensures all uncaught exceptions are written to the persistent log file."""
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        target_logger.critical("Uncaught exception in agent service:", exc_info=(exc_type, exc_value, exc_traceback))
    sys.excepthook = handle_exception

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

    # 1. File Handler (Always active in DATA_DIR)
    try:
        file_handler = logging.FileHandler(str(LOG_FILE), encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        if sys.stderr and hasattr(sys.stderr, "write"):
            try:
                sys.stderr.write(f"Warning: Could not initialize log file at {LOG_FILE}: {e}\n")
            except Exception:
                pass

    # 2. Console Handler (stdout) - Only if attached to a real console
    if sys.stdout is not None and not isinstance(sys.stdout, SafeStreamWrapper):
        try:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        except Exception:
            pass

    # 3. Redirect None stdio streams in windowless mode to prevent crashes and capture output
    if sys.stdout is None:
        sys.stdout = SafeStreamWrapper(logger, logging.INFO)
    if sys.stderr is None:
        sys.stderr = SafeStreamWrapper(logger, logging.ERROR)

    install_exception_hook(logger)
    return logger

logger = setup_logger()
