"""
PhantomTrace Behavioral Detection Engine
PhantomTrace Release 1.0

Read-only behavioral analysis.

Important:
- Behavioral indicators are evidence only.
- No process is automatically classified as malware.
- The engine produces normalized indicators that can be
  consumed by the threat scoring engine.
"""

from typing import Any, Dict, List


# ============================================================
# SCRIPT INTERPRETERS
# ============================================================

SCRIPT_INTERPRETERS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
}


# ============================================================
# UNUSUAL SCRIPT PARENTS
# ============================================================

UNUSUAL_SCRIPT_PARENTS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
}


# ============================================================
# SUSPICIOUS PATHS
# ============================================================

SUSPICIOUS_PATH_KEYWORDS = (
    "\\temp\\",
    "\\downloads\\",
    "\\appdata\\local\\temp\\",
)


# ============================================================
# NORMALIZE COMMAND LINE
# ============================================================

def normalize_cmdline(
    value: Any,
) -> str:

    if value is None:
        return ""

    if isinstance(
        value,
        list,
    ):

        return " ".join(
            str(item)
            for item in value
        ).lower()

    return str(
        value
    ).lower()


# ============================================================
# NORMALIZE INDICATORS
# ============================================================

def normalize_indicators(
    indicators: List[Any],
) -> List[str]:

    normalized = []

    for item in indicators:

        if isinstance(
            item,
            dict,
        ):

            indicator_type = (
                item.get("type")
                or item.get("indicator")
                or item.get("name")
            )

            if indicator_type:
                normalized.append(
                    str(
                        indicator_type
                    )
                )

        elif item is not None:

            normalized.append(
                str(item)
            )

    return list(
        dict.fromkeys(
            normalized
        )
    )


# ============================================================
# ANALYZE PROCESS
# ============================================================

def analyze_process(
    process: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Analyze one process.

    Returns:
        score
        status
        indicator_count
        indicators
        raw_indicators
    """

    if not isinstance(
        process,
        dict,
    ):

        process = {}

    indicators = []

    raw_indicators = []

    score = 0

    # --------------------------------------------------------
    # Process information
    # --------------------------------------------------------

    name = str(
        process.get(
            "name",
            "",
        )
        or ""
    ).lower()

    exe = str(
        process.get(
            "exe",
            "",
        )
        or ""
    ).lower()

    cmdline = normalize_cmdline(
        process.get(
            "cmdline"
        )
    )

    parent_name = str(
        process.get(
            "parent_name",
            "",
        )
        or ""
    ).lower()

    # --------------------------------------------------------
    # 1. Script interpreter
    # --------------------------------------------------------

    if name in SCRIPT_INTERPRETERS:

        indicators.append(
            "SCRIPT_INTERPRETER_ACTIVITY"
        )

        raw_indicators.append({

            "type":
                "script_interpreter",

            "description":
                "Process is a script interpreter "
                "and receives additional analysis.",

            "evidence":
                process.get(
                    "name"
                ),
        })

        score += 5

    # --------------------------------------------------------
    # 2. Suspicious executable location
    # --------------------------------------------------------

    if exe:

        for keyword in (
            SUSPICIOUS_PATH_KEYWORDS
        ):

            if keyword in exe:

                indicators.append(
                    "SUSPICIOUS_EXECUTION_CONTEXT"
                )

                raw_indicators.append({

                    "type":
                        "unusual_location",

                    "description":
                        "Executable is running from "
                        "a location requiring "
                        "additional scrutiny.",

                    "evidence":
                        process.get(
                            "exe"
                        ),
                })

                score += 15

                break

    # --------------------------------------------------------
    # 3. Suspicious command line
    # --------------------------------------------------------

    suspicious_patterns = (
        "-encodedcommand",
        "-enc ",
        "frombase64string",
        "downloadstring",
        "downloadfile",
        "invoke-expression",
        "iex ",
    )

    matched_pattern = None

    for pattern in (
        suspicious_patterns
    ):

        if pattern in cmdline:

            matched_pattern = pattern
            break

    if matched_pattern:

        indicators.append(
            "SUSPICIOUS_COMMAND_LINE"
        )

        raw_indicators.append({

            "type":
                "suspicious_command",

            "description":
                "Command line contains a "
                "pattern requiring "
                "additional investigation.",

            "evidence":
                matched_pattern,
        })

        score += 15

    # --------------------------------------------------------
    # 4. Fileless indicator
    # --------------------------------------------------------

    if (
        "powershell" in cmdline
        and
        (
            "-enc" in cmdline
            or
            "-encodedcommand"
            in cmdline
        )
    ):

        indicators.append(
            "FILELESS_INDICATOR"
        )

        raw_indicators.append({

            "type":
                "fileless_indicator",

            "description":
                "PowerShell command line "
                "contains an encoded command.",

            "evidence":
                cmdline,
        })

        score += 30

    # --------------------------------------------------------
    # 5. Suspicious parent
    # --------------------------------------------------------

    if (
        name in SCRIPT_INTERPRETERS
        and
        parent_name
        in UNUSUAL_SCRIPT_PARENTS
    ):

        indicators.append(
            "SUSPICIOUS_PARENT"
        )

        raw_indicators.append({

            "type":
                "unusual_parent",

            "description":
                "A script interpreter was "
                "launched by an application "
                "requiring additional scrutiny.",

            "evidence":
                f"{parent_name} -> {name}",
        })

        score += 20

    # --------------------------------------------------------
    # 6. Path unavailable
    #
    # Do NOT treat this as meaningful threat evidence.
    # It is preserved as raw evidence but does not increase
    # the unified threat score.
    # --------------------------------------------------------

    path_unavailable = not bool(
        exe
    )

    if path_unavailable:

        raw_indicators.append({

            "type":
                "path_unavailable",

            "description":
                "Executable path could not be "
                "collected. This may occur "
                "because of Windows permissions.",

            "evidence":
                None,
        })

    # --------------------------------------------------------
    # Normalize
    # --------------------------------------------------------

    indicators = normalize_indicators(
        indicators
    )

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

    if score >= 60:

        status = "HIGH"

    elif score >= 30:

        status = "MEDIUM"

    elif score > 0:

        status = "LOW"

    else:

        status = "NORMAL"

    return {

        "score":
            min(
                score,
                100,
            ),

        "status":
            status,

        "indicator_count":
            len(indicators),

        "indicators":
            indicators,

        "raw_indicators":
            raw_indicators,

        "path_unavailable":
            path_unavailable,
    }


# ============================================================
# ANALYZE ALL PROCESSES
# ============================================================

def analyze_processes(
    processes: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    results = []

    for process in processes:

        if not isinstance(
            process,
            dict,
        ):
            continue

        behavior = analyze_process(
            process
        )

        results.append({

            "pid":
                process.get(
                    "pid"
                ),

            "name":
                process.get(
                    "name"
                ),

            "behavior":
                behavior,
        })

    return results


# ============================================================
# SUMMARY
# ============================================================

def summarize_behavior(
    results: List[Dict[str, Any]],
) -> Dict[str, Any]:

    summary = {

        "total":
            len(results),

        "normal":
            0,

        "low":
            0,

        "medium":
            0,

        "high":
            0,

        "alerts":
            0,
    }

    for result in results:

        behavior = result.get(
            "behavior",
            {},
        )

        status = str(
            behavior.get(
                "status",
                "NORMAL",
            )
        ).lower()

        if status == "normal":

            summary["normal"] += 1

        elif status == "low":

            summary["low"] += 1
            summary["alerts"] += 1

        elif status == "medium":

            summary["medium"] += 1
            summary["alerts"] += 1

        elif status == "high":

            summary["high"] += 1
            summary["alerts"] += 1

    return summary
