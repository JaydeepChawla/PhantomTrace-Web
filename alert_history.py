"""
PHANTOMTRACE
Alert History Module
Phase 4

Stores PhantomTrace alert records locally.

This does NOT modify, delete, quarantine,
or kill endpoint processes/files.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


# ============================================================
# CONFIGURATION
# ============================================================

HISTORY_FILE = Path(
    "alert_history.json"
)

MAX_HISTORY = 500


# ============================================================
# LOAD HISTORY
# ============================================================

def load_alert_history() -> List[
    Dict[str, Any]
]:

    if not HISTORY_FILE.exists():
        return []

    try:

        with HISTORY_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(
                file
            )

        if isinstance(
            data,
            list,
        ):
            return data

        return []

    except (
        OSError,
        json.JSONDecodeError,
    ):

        return []


# ============================================================
# SAVE HISTORY
# ============================================================

def save_alert_history(
    history: List[
        Dict[str, Any]
    ],
) -> None:

    try:

        with HISTORY_FILE.open(
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                history[
                    -MAX_HISTORY:
                ],
                file,
                indent=2,
                ensure_ascii=False,
            )

    except OSError:
        pass


# ============================================================
# PERSIST ALERTS
# ============================================================

def persist_alerts(
    alerts: List[
        Dict[str, Any]
    ],
) -> List[
    Dict[str, Any]
]:

    history = load_alert_history()

    timestamp = (
        datetime.now().isoformat()
    )

    if not isinstance(
        alerts,
        list,
    ):
        alerts = []

    for alert in alerts:

        if not isinstance(
            alert,
            dict,
        ):
            continue

        entry = dict(
            alert
        )

        entry[
            "timestamp"
        ] = timestamp

        history.append(
            entry
        )

    history = history[
        -MAX_HISTORY:
    ]

    save_alert_history(
        history
    )

    return history


# ============================================================
# PRINT HISTORY SUMMARY
# ============================================================

def print_history_summary(
    history: List[
        Dict[str, Any]
    ],
) -> None:

    if not isinstance(
        history,
        list,
    ):
        history = []

    critical = 0
    high = 0
    medium = 0
    low = 0

    for alert in history:

        if not isinstance(
            alert,
            dict,
        ):
            continue

        level = str(
            alert.get(
                "level",
                "",
            )
        ).upper()

        if level == "CRITICAL":
            critical += 1

        elif level == "HIGH":
            high += 1

        elif level == "MEDIUM":
            medium += 1

        elif level == "LOW":
            low += 1

    print()
    print("=" * 70)
    print(
        "             PHANTOMTRACE ALERT HISTORY"
    )
    print("=" * 70)
    print()

    print(
        f"History Records : "
        f"{len(history)}"
    )

    print(
        f"Critical        : "
        f"{critical}"
    )

    print(
        f"High            : "
        f"{high}"
    )

    print(
        f"Medium          : "
        f"{medium}"
    )

    print(
        f"Low             : "
        f"{low}"
    )

    print()
    print("=" * 70)


# ============================================================
# CLEAR HISTORY
# ============================================================

def clear_alert_history() -> None:

    try:

        if HISTORY_FILE.exists():

            HISTORY_FILE.unlink()

    except OSError:
        pass