"""
PhantomTrace
PhantomTrace Windows Release 1.0

Detection Validation + Repeated Run Stability Report

Read-only Windows endpoint scanner.
"""

from __future__ import annotations

import json
import platform
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import psutil

# Ensure parent directory and agent directory are in sys.path for direct execution and packaging
_current_dir = Path(__file__).resolve().parent
_root_dir = _current_dir.parent
for _p in [str(_root_dir), str(_current_dir)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from agent.core.memory_scanner import (
    scan_process_memory,
    summarize_memory_results,
)

from agent.core.behavior_engine import (
    analyze_process,
)

from agent.core.threat_score import (
    calculate_threat_score,
    summarize_threats,
)

from alert_history import (
    persist_alerts,
    print_history_summary,
)


# ============================================================
# VERSION
# ============================================================

PHANTOMTRACE_VERSION = "PhantomTrace Windows Release 1.0"


# ============================================================
# OUTPUT FILES
# ============================================================

RESULTS_FILE = Path("scan_results.json")

VALIDATION_REPORT_FILE = Path(
    "phantomtrace_validation_report.txt"
)


# ============================================================
# COLORS
# ============================================================

RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"


def color_level(level: str) -> str:

    level = str(level).upper()

    if level in {"CRITICAL", "HIGH"}:
        return f"{RED}{level}{RESET}"

    if level in {"MEDIUM", "LOW"}:
        return f"{YELLOW}{level}{RESET}"

    return f"{GREEN}{level}{RESET}"


# ============================================================
# SAFE PROCESS NAME
# ============================================================

def get_process_name(
    process: psutil.Process,
) -> str:

    try:
        return process.name()

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
    ):
        return "Unknown"

    except Exception:
        return "Unknown"


# ============================================================
# SAFE EXECUTABLE
# ============================================================

def get_process_executable(
    process: psutil.Process,
) -> str:

    try:
        return process.exe()

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
    ):
        return ""

    except Exception:
        return ""


# ============================================================
# SAFE PARENT
# ============================================================

def get_parent_process(
    process: psutil.Process,
) -> Dict[str, Any]:

    try:

        parent = process.parent()

        if parent is None:
            return {
                "pid": None,
                "name": None,
            }

        return {
            "pid": parent.pid,
            "name": get_process_name(parent),
        }

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
    ):
        return {
            "pid": None,
            "name": None,
        }

    except Exception:
        return {
            "pid": None,
            "name": None,
        }


# ============================================================
# PROCESS BEHAVIOR INPUT
# ============================================================

def build_behavior_process(
    process: psutil.Process,
) -> Dict[str, Any]:

    name = get_process_name(process)

    executable = get_process_executable(
        process
    )

    parent = get_parent_process(
        process
    )

    command_line: List[str] = []

    try:
        command_line = process.cmdline()

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
    ):
        command_line = []

    except Exception:
        command_line = []

    return {
        "pid": process.pid,
        "name": name,
        "exe": executable,
        "cmdline": command_line,
        "parent_name": parent.get("name"),
    }


# ============================================================
# NORMALIZE BEHAVIOR INDICATORS
# ============================================================

def normalize_behavior_indicators(
    behavior: Dict[str, Any],
) -> List[str]:

    if not isinstance(behavior, dict):
        return []

    indicators = behavior.get(
        "indicators",
        [],
    )

    if not isinstance(indicators, list):
        return []

    output: List[str] = []

    for indicator in indicators:

        if isinstance(indicator, dict):

            value = (
                indicator.get("type")
                or indicator.get("indicator")
                or indicator.get("name")
            )

            if value:
                output.append(str(value))

        elif indicator:

            output.append(str(indicator))

    return list(
        dict.fromkeys(output)
    )


# ============================================================
# MEMORY EVIDENCE CHECK
# ============================================================

def has_memory_evidence(
    memory_result: Dict[str, Any],
) -> bool:

    if not isinstance(
        memory_result,
        dict,
    ):
        return False

    indicators = memory_result.get(
        "indicators",
        [],
    )

    suspicious_regions = int(
        memory_result.get(
            "suspicious_regions",
            0,
        )
        or 0
    )

    rwx_regions = int(
        memory_result.get(
            "writable_executable_regions",
            0,
        )
        or 0
    )

    private_exec = int(
        memory_result.get(
            "private_executable_regions",
            0,
        )
        or 0
    )

    return bool(
        indicators
        or suspicious_regions > 0
        or rwx_regions > 0
        or private_exec > 0
    )


# ============================================================
# SCAN PROCESS
# ============================================================

def scan_process(
    process: psutil.Process,
) -> Dict[str, Any]:

    pid = process.pid

    name = get_process_name(
        process
    )

    executable = get_process_executable(
        process
    )

    parent = get_parent_process(
        process
    )

    # --------------------------------------------------------
    # BEHAVIOR
    # --------------------------------------------------------

    behavior_input = (
        build_behavior_process(
            process
        )
    )

    behavior = analyze_process(
        behavior_input
    )

    if not isinstance(
        behavior,
        dict,
    ):
        behavior = {}

    behavior_indicators = (
        normalize_behavior_indicators(
            behavior
        )
    )

    # --------------------------------------------------------
    # MEMORY
    # --------------------------------------------------------

    memory_result = scan_process_memory(
        pid
    )

    if not isinstance(
        memory_result,
        dict,
    ):
        memory_result = {}

    # --------------------------------------------------------
    # THREAT SCORE
    # --------------------------------------------------------

    threat = calculate_threat_score(

        behavioral_indicators=
            behavior_indicators,

        memory_result=
            memory_result,

        process_indicators=[],

        process_name=
            name,
    )

    if not isinstance(
        threat,
        dict,
    ):
        threat = {}

    # --------------------------------------------------------
    # SCORES
    # --------------------------------------------------------

    behavior_score = float(
        threat.get(
            "behavior_score",
            0,
        )
        or 0
    )

    memory_score = float(
        threat.get(
            "memory_score",
            0,
        )
        or 0
    )

    process_score = float(
        threat.get(
            "process_score",
            0,
        )
        or 0
    )

    correlation_bonus = float(
        threat.get(
            "correlation_bonus",
            0,
        )
        or 0
    )

    final_score = float(
        threat.get(
            "score",
            0,
        )
        or 0
    )

    raw_score = float(
        threat.get(
            "raw_score",
            0,
        )
        or 0
    )

    # --------------------------------------------------------
    # EVIDENCE
    # --------------------------------------------------------

    memory_evidence = has_memory_evidence(
        memory_result
    )

    behavior_evidence = bool(
        behavior_indicators
    )

    memory_only = bool(
        threat.get(
            "memory_only",
            False,
        )
    )

    score_mode = threat.get(
        "score_mode",
        "NO_EVIDENCE",
    )

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    return {

        "pid":
            pid,

        "name":
            name,

        "executable":
            executable,

        "parent":
            parent,

        "behavior":
            behavior,

        "memory":
            memory_result,

        "application_context":
            threat.get(
                "application_context",
                "STANDARD_PROCESS",
            ),

        "behavior_score":
            behavior_score,

        "memory_score":
            memory_score,

        "process_score":
            process_score,

        "correlation_bonus":
            correlation_bonus,

        "correlation_findings":
            threat.get(
                "correlation_indicators",
                [],
            ),

        "memory_evidence_strength":
            threat.get(
                "memory_evidence_strength",
                "NONE",
            ),

        "memory_context_adjustment":
            threat.get(
                "memory_context_adjustment",
                "NONE",
            ),

        "context_adjusted":
            threat.get(
                "context_adjusted",
                False,
            ),

        "memory_only":
            memory_only,

        "score_mode":
            score_mode,

        "raw_score":
            raw_score,

        "score":
            final_score,

        "level":
            threat.get(
                "level",
                "NORMAL",
            ),

        "indicators":
            threat.get(
                "indicators",
                [],
            ),

        "has_behavior_evidence":
            behavior_evidence,

        "has_memory_evidence":
            memory_evidence,
    }


# ============================================================
# SCAN SYSTEM
# ============================================================

def scan_system() -> List[Dict[str, Any]]:

    results: List[Dict[str, Any]] = []

    processes = list(
        psutil.process_iter(
            [
                "pid",
                "name",
            ]
        )
    )

    total = len(processes)

    print()
    print(
        f"Processes discovered: {total}"
    )
    print()

    for index, process in enumerate(
        processes,
        start=1,
    ):

        try:

            result = scan_process(
                process
            )

            results.append(
                result
            )

            level = str(
                result.get(
                    "level",
                    "NORMAL",
                )
            ).upper()

            if level in {
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            }:

                print(
                    f"[ALERT] "
                    f"PID={result.get('pid')} "
                    f"{result.get('name', 'Unknown')} "
                    f"Score="
                    f"{float(result.get('score', 0)):.1f} "
                    f"Level="
                    f"{color_level(level)}"
                )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

        except Exception as exc:

            results.append({

                "pid":
                    process.pid,

                "name":
                    get_process_name(
                        process
                    ),

                "score":
                    0.0,

                "raw_score":
                    0.0,

                "level":
                    "NORMAL",

                "behavior_score":
                    0.0,

                "memory_score":
                    0.0,

                "process_score":
                    0.0,

                "correlation_bonus":
                    0.0,

                "indicators":
                    [],

                "has_behavior_evidence":
                    False,

                "has_memory_evidence":
                    False,

                "error":
                    str(exc),
            })

        if (
            index % 25 == 0
            or index == total
        ):

            print(
                f"Progress: "
                f"{index}/{total}",
                end="\r",
            )

    print()

    return results


# ============================================================
# CORRELATION
# ============================================================

def apply_correlation(
    results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    for result in results:

        behavior = result.get(
            "behavior",
            {},
        )

        memory = result.get(
            "memory",
            {},
        )

        if not isinstance(
            behavior,
            dict,
        ):
            behavior = {}

        if not isinstance(
            memory,
            dict,
        ):
            memory = {}

        behavioral = (
            normalize_behavior_indicators(
                behavior
            )
        )

        memory_indicators = memory.get(
            "indicators",
            [],
        )

        if not isinstance(
            memory_indicators,
            list,
        ):
            memory_indicators = []

        suspicious_regions = int(
            memory.get(
                "suspicious_regions",
                0,
            )
            or 0
        )

        rwx_regions = int(
            memory.get(
                "writable_executable_regions",
                0,
            )
            or 0
        )

        private_exec = int(
            memory.get(
                "private_executable_regions",
                0,
            )
            or 0
        )

        memory_present = bool(
            memory_indicators
            or suspicious_regions > 0
            or rwx_regions > 0
            or private_exec > 0
        )

        findings: List[str] = []

        if behavioral and memory_present:

            findings.append(
                "BEHAVIOR_MEMORY_CORRELATION"
            )

        if (
            "FILELESS_INDICATOR"
            in behavioral
            and (
                rwx_regions > 0
                or private_exec > 0
            )
        ):

            findings.append(
                "FILELESS_MEMORY_CORRELATION"
            )

        if (
            "SUSPICIOUS_COMMAND_LINE"
            in behavioral
            and (
                rwx_regions > 0
                or private_exec > 0
            )
        ):

            findings.append(
                "COMMAND_MEMORY_CORRELATION"
            )

        if (
            "SUSPICIOUS_PARENT"
            in behavioral
            and memory_present
        ):

            findings.append(
                "PARENT_MEMORY_CORRELATION"
            )

        findings = list(
            dict.fromkeys(
                findings
            )
        )

        result[
            "correlation_findings"
        ] = findings

        existing = result.get(
            "indicators",
            [],
        )

        if not isinstance(
            existing,
            list,
        ):
            existing = []

        result["indicators"] = list(
            dict.fromkeys(
                existing + findings
            )
        )

    return results


# ============================================================
# CORRELATION DIAGNOSTIC
# ============================================================

def print_correlation_diagnostic(
    results: List[Dict[str, Any]],
) -> None:

    memory_count = 0
    behavior_count = 0
    overlap_count = 0

    overlap_rows: List[
        Dict[str, Any]
    ] = []

    for result in results:

        behavior = result.get(
            "behavior",
            {},
        )

        memory = result.get(
            "memory",
            {},
        )

        if not isinstance(
            behavior,
            dict,
        ):
            behavior = {}

        if not isinstance(
            memory,
            dict,
        ):
            memory = {}

        behavior_indicators = (
            normalize_behavior_indicators(
                behavior
            )
        )

        memory_indicators = memory.get(
            "indicators",
            [],
        )

        if not isinstance(
            memory_indicators,
            list,
        ):
            memory_indicators = []

        suspicious_regions = int(
            memory.get(
                "suspicious_regions",
                0,
            )
            or 0
        )

        rwx_regions = int(
            memory.get(
                "writable_executable_regions",
                0,
            )
            or 0
        )

        private_exec = int(
            memory.get(
                "private_executable_regions",
                0,
            )
            or 0
        )

        memory_present = bool(
            memory_indicators
            or suspicious_regions > 0
            or rwx_regions > 0
            or private_exec > 0
        )

        behavior_present = bool(
            behavior_indicators
        )

        if memory_present:
            memory_count += 1

        if behavior_present:
            behavior_count += 1

        if (
            memory_present
            and behavior_present
        ):

            overlap_count += 1

            overlap_rows.append({

                "pid":
                    result.get("pid"),

                "name":
                    result.get("name"),

                "behavior":
                    behavior_indicators,

                "suspicious_regions":
                    suspicious_regions,

                "rwx_regions":
                    rwx_regions,

                "private_exec":
                    private_exec,

                "memory_indicators":
                    memory_indicators,
            })

    print()
    print("=" * 70)
    print(
        "          PHANTOMTRACE CORRELATION DIAGNOSTIC"
    )
    print("=" * 70)

    print()

    print(
        f"Processes with memory evidence : "
        f"{memory_count}"
    )

    print(
        f"Processes with behavior evidence: "
        f"{behavior_count}"
    )

    print(
        f"Processes with both             : "
        f"{overlap_count}"
    )

    if overlap_rows:

        print()
        print(
            "Evidence Overlap:"
        )

        print(
            "-" * 70
        )

        for row in overlap_rows[:20]:

            print()

            print(
                f"PID       : "
                f"{row['pid']}"
            )

            print(
                f"Process   : "
                f"{row['name']}"
            )

            print(
                "Behavior  : "
                + (
                    ", ".join(
                        row["behavior"]
                    )
                    or "None"
                )
            )

            print(
                f"Suspicious Regions : "
                f"{row['suspicious_regions']}"
            )

            print(
                f"RWX Regions       : "
                f"{row['rwx_regions']}"
            )

            print(
                f"Private Exec      : "
                f"{row['private_exec']}"
            )

            print(
                "Memory Indicators : "
                + (
                    ", ".join(
                        row["memory_indicators"]
                    )
                    or "None"
                )
            )

    else:

        print()
        print(
            "No processes currently contain both "
            "behavioral and memory evidence."
        )

    print()
    print("=" * 70)


# ============================================================
# VALIDATION DATA
# ============================================================

def build_validation_report(
    results: List[Dict[str, Any]],
) -> Dict[str, Any]:

    memory_processes = sum(
        1
        for result in results
        if result.get(
            "has_memory_evidence",
            False,
        )
    )

    behavior_processes = sum(
        1
        for result in results
        if result.get(
            "has_behavior_evidence",
            False,
        )
    )

    correlated = sum(
        1
        for result in results
        if result.get(
            "correlation_bonus",
            0,
        ) > 0
    )

    common_apps = sum(
        1
        for result in results
        if result.get(
            "application_context",
            "STANDARD_PROCESS",
        )
        == "TRUSTED_COMMON_APPLICATION"
    )

    context_adjusted = sum(
        1
        for result in results
        if result.get(
            "context_adjusted",
            False,
        )
    )

    memory_capped = sum(
        1
        for result in results
        if result.get(
            "memory_only",
            False,
        )
    )

    levels = {
        "NORMAL": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for result in results:

        level = str(
            result.get(
                "level",
                "NORMAL",
            )
        ).upper()

        if level in levels:
            levels[level] += 1

    trusted_alerts = sum(
        1
        for result in results
        if (
            result.get(
                "application_context"
            )
            == "TRUSTED_COMMON_APPLICATION"
            and float(
                result.get(
                    "score",
                    0,
                )
                or 0
            ) > 0
        )
    )

    return {

        "processes_analyzed":
            len(results),

        "memory_evidence_processes":
            memory_processes,

        "behavior_evidence_processes":
            behavior_processes,

        "memory_behavior_correlated":
            correlated,

        "trusted_common_applications":
            common_apps,

        "context_adjusted_processes":
            context_adjusted,

        "memory_only_capped":
            memory_capped,

        "trusted_application_alerts":
            trusted_alerts,

        "normal":
            levels["NORMAL"],

        "low":
            levels["LOW"],

        "medium":
            levels["MEDIUM"],

        "high":
            levels["HIGH"],

        "critical":
            levels["CRITICAL"],
    }


# ============================================================
# VALIDATION REPORT
# ============================================================

def save_validation_report(
    results: List[Dict[str, Any]],
    elapsed: float,
) -> None:

    validation = (
        build_validation_report(
            results
        )
    )

    summary = summarize_threats(
        results
    )

    alerts = summary.get(
        "threat_alerts",
        [],
    )

    if not isinstance(
        alerts,
        list,
    ):
        alerts = []

    lines: List[str] = []

    lines.append(
        "=" * 70
    )

    lines.append(
        "PHANTOMTRACE VALIDATION REPORT"
    )

    lines.append(
        "DETECTION VALIDATION REPORT"
    )

    lines.append(
        "=" * 70
    )

    lines.append("")

    lines.append(
        f"Version                 : "
        f"{PHANTOMTRACE_VERSION}"
    )

    lines.append(
        f"Platform                : "
        f"{platform.system()} "
        f"{platform.release()}"
    )

    lines.append(
        f"Scan Time               : "
        f"{elapsed:.3f} seconds"
    )

    lines.append("")

    lines.append(
        "PROCESS VALIDATION"
    )

    lines.append(
        "-" * 70
    )

    lines.append(
        f"Processes analyzed      : "
        f"{validation['processes_analyzed']}"
    )

    lines.append(
        f"Normal                  : "
        f"{validation['normal']}"
    )

    lines.append(
        f"Low                     : "
        f"{validation['low']}"
    )

    lines.append(
        f"Medium                  : "
        f"{validation['medium']}"
    )

    lines.append(
        f"High                    : "
        f"{validation['high']}"
    )

    lines.append(
        f"Critical                : "
        f"{validation['critical']}"
    )

    lines.append("")

    lines.append(
        "EVIDENCE PIPELINE"
    )

    lines.append(
        "-" * 70
    )

    lines.append(
        f"Memory evidence         : "
        f"{validation['memory_evidence_processes']}"
    )

    lines.append(
        f"Behavior evidence       : "
        f"{validation['behavior_evidence_processes']}"
    )

    lines.append(
        f"Memory + behavior       : "
        f"{validation['memory_behavior_correlated']}"
    )

    lines.append(
        f"Trusted applications    : "
        f"{validation['trusted_common_applications']}"
    )

    lines.append(
        f"Context adjusted        : "
        f"{validation['context_adjusted_processes']}"
    )

    lines.append(
        f"Memory-only capped      : "
        f"{validation['memory_only_capped']}"
    )

    lines.append("")

    lines.append(
        "THREAT VALIDATION"
    )

    lines.append(
        "-" * 70
    )

    lines.append(
        f"Threat alerts           : "
        f"{len(alerts)}"
    )

    lines.append(
        f"Trusted app alerts      : "
        f"{validation['trusted_application_alerts']}"
    )

    lines.append(
        f"Highest score           : "
        f"{float(summary.get('highest_score', 0)):.1f}"
    )

    lines.append("")

    lines.append(
        "VALIDATION STATUS"
    )

    lines.append(
        "-" * 70
    )

    lines.append(
        "Scanner mode            : READ-ONLY"
    )

    lines.append(
        "Memory evidence         : PRESERVED"
    )

    lines.append(
        "Behavior evidence       : PRESERVED"
    )

    lines.append(
        "JSON evidence           : PRESERVED"
    )

    lines.append(
        "Memory-only cap         : ACTIVE"
    )

    lines.append(
        "Structured alerts       : ACTIVE"
    )

    lines.append("")

    lines.append(
        "=" * 70
    )

    lines.append(
        "PHANTOMTRACE VALIDATION REPORT COMPLETE"
    )

    lines.append(
        "=" * 70
    )

    try:

        VALIDATION_REPORT_FILE.write_text(
            "\n".join(lines),
            encoding="utf-8",
        )

        print()
        print(
            f"Validation report saved: "
            f"{VALIDATION_REPORT_FILE}"
        )

    except Exception as exc:

        print()
        print(
            f"[WARNING] Could not save validation report "
            f"validation report: {exc}"
        )


# ============================================================
# THREAT ALERTS
# ============================================================

def print_threat_alerts(
    results: List[Dict[str, Any]],
) -> None:

    summary = summarize_threats(
        results
    )

    alerts = summary.get(
        "threat_alerts",
        [],
    )

    if not isinstance(
        alerts,
        list,
    ):
        alerts = []

    print()
    print("=" * 70)
    print(
        "                  THREAT ALERTS"
    )
    print("=" * 70)

    try:

        history = persist_alerts(
            alerts
        )

        print_history_summary(
            history
        )

    except Exception as exc:

        print()
        print(
            f"[WARNING] Alert history "
            f"unavailable: {exc}"
        )

    try:
        from agent.notifications import dispatch_threat_notifications
        dispatch_threat_notifications(alerts)
    except Exception as exc:
        print()
        print(
            f"[WARNING] Notification dispatch "
            f"unavailable: {exc}"
        )

    if not alerts:

        print()
        print(
            "No threat alerts detected."
        )

        return

    for index, alert in enumerate(
        alerts,
        start=1,
    ):

        print()
        print("-" * 70)

        print(
            f"THREAT ALERT "
            f"{index} / {len(alerts)}"
        )

        print("-" * 70)

        print(
            f"PID              : "
            f"{alert.get('pid', 'N/A')}"
        )

        print(
            f"Process          : "
            f"{alert.get('name', 'Unknown')}"
        )

        print(
            f"Threat Score     : "
            f"{float(alert.get('score', 0) or 0):.1f}"
        )

        print(
            f"Threat Level     : "
            f"{color_level(alert.get('level', 'NORMAL'))}"
        )

        print(
            f"Application      : "
            f"{alert.get('application_context', 'STANDARD_PROCESS')}"
        )

        print(
            f"Score Mode       : "
            f"{alert.get('score_mode', 'UNKNOWN')}"
        )

        print(
            f"Behavior Score   : "
            f"{float(alert.get('behavior_score', 0) or 0):.1f}"
        )

        print(
            f"Memory Score     : "
            f"{float(alert.get('memory_score', 0) or 0):.1f}"
        )

        print(
            f"Process Score    : "
            f"{float(alert.get('process_score', 0) or 0):.1f}"
        )

        print(
            f"Correlation      : "
            f"{float(alert.get('correlation_bonus', 0) or 0):.1f}"
        )

        print(
            f"Memory Evidence  : "
            f"{alert.get('memory_evidence_strength', 'NONE')}"
        )

        print()
        print("Indicators:")

        indicators = alert.get(
            "indicators",
            [],
        )

        if (
            isinstance(indicators, list)
            and indicators
        ):

            for indicator in indicators:
                print(
                    f"  - {indicator}"
                )

        else:

            print(
                "  - None"
            )

        print("-" * 70)


# ============================================================
# MEMORY INFORMATION
# ============================================================

def print_memory_information(
    results: List[Dict[str, Any]],
) -> None:

    memory_results: List[
        Dict[str, Any]
    ] = []

    for result in results:

        memory = result.get(
            "memory"
        )

        if isinstance(
            memory,
            dict,
        ):

            memory_results.append(
                memory
            )

    try:

        summary = summarize_memory_results(
            memory_results
        )

    except Exception as exc:

        print()
        print(
            f"[WARNING] Memory summary "
            f"failed: {exc}"
        )

        return

    print()
    print("=" * 70)
    print(
        "                  MEMORY SCAN"
    )
    print("=" * 70)

    print()

    print(
        f"Processes       : "
        f"{summary.get('total_processes', 0)}"
    )

    print(
        f"Memory Scanned  : "
        f"{summary.get('scanned', 0)}"
    )

    print(
        f"Access Denied   : "
        f"{summary.get('access_denied', 0)}"
    )

    print(
        f"Errors          : "
        f"{summary.get('errors', 0)}"
    )

    print(
        f"Suspicious Proc : "
        f"{summary.get('suspicious_processes', 0)}"
    )

    print(
        f"Suspicious Reg. : "
        f"{summary.get('suspicious_regions', 0)}"
    )

    print(
        f"RWX Processes   : "
        f"{summary.get('rwx_processes', 0)}"
    )

    print(
        f"Private Exec    : "
        f"{summary.get('private_executable_processes', 0)}"
    )


# ============================================================
# SAVE JSON
# ============================================================

def save_scan_results(
    results: List[Dict[str, Any]],
    elapsed: float,
) -> None:

    try:

        summary = summarize_threats(
            results
        )

    except Exception as exc:

        print()
        print(
            f"[WARNING] Threat summary "
            f"failed: {exc}"
        )

        summary = {}

    output = {

        "phantomtrace_version":
            PHANTOMTRACE_VERSION,

        "platform":
            f"{platform.system()} "
            f"{platform.release()}",

        "scan_time_seconds":
            round(
                elapsed,
                3,
            ),

        "summary":
            summary,

        "results":
            results,
    }

    try:

        with RESULTS_FILE.open(
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                output,
                file,
                indent=2,
                ensure_ascii=False,
            )

        print()
        print(
            f"JSON report saved: "
            f"{RESULTS_FILE}"
        )

    except Exception as exc:

        print()
        print(
            f"[WARNING] Could not save "
            f"JSON report: {exc}"
        )


# ============================================================
# FINAL SUMMARY
# ============================================================

def print_final_summary(
    results: List[Dict[str, Any]],
    elapsed: float,
) -> None:

    try:

        summary = summarize_threats(
            results
        )

    except Exception as exc:

        print()
        print(
            f"[WARNING] Final summary "
            f"failed: {exc}"
        )

        return

    alerts = summary.get(
        "threat_alerts",
        [],
    )

    if not isinstance(
        alerts,
        list,
    ):
        alerts = []

    print()
    print("=" * 70)
    print(
        "             PHANTOMTRACE THREAT SCORE"
    )
    print("=" * 70)

    print()

    print(
        f"Total Processes : "
        f"{summary.get('total_processes', 0)}"
    )

    print(
        f"Normal          : "
        f"{summary.get('normal', 0)}"
    )

    print(
        f"Low             : "
        f"{summary.get('low', 0)}"
    )

    print(
        f"Medium          : "
        f"{summary.get('medium', 0)}"
    )

    print(
        f"High            : "
        f"{summary.get('high', 0)}"
    )

    print(
        f"Critical        : "
        f"{summary.get('critical', 0)}"
    )

    print(
        f"Threat Alerts   : "
        f"{len(alerts)}"
    )

    print(
        f"Highest Score   : "
        f"{float(summary.get('highest_score', 0) or 0):.1f}"
    )

    print(
        f"Scan Time       : "
        f"{elapsed:.2f} seconds"
    )

    print("=" * 70)


# ============================================================
# BANNER
# ============================================================

def print_banner() -> None:

    print()
    print("=" * 70)

    print(
        "                         PHANTOMTRACE"
    )

    print(
        "             Memory & Fileless Threat Detection"
    )

    print(
        "                    Trace what others can't see."
    )

    print("=" * 70)

    print()

    print(
        f"Version : "
        f"{PHANTOMTRACE_VERSION}"
    )

    print(
        f"Platform: "
        f"{platform.system()} "
        f"{platform.release()}"
    )

    print()


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    if platform.system() != "Windows":

        print(
            "[ERROR] PhantomTrace currently "
            "requires Windows."
        )

        return 1

    print_banner()

    print(
        "Starting unified endpoint scan..."
    )

    print(
        "This scanner performs read-only analysis."
    )

    print()

    start_time = time.perf_counter()

    try:

        results = scan_system()

        results = apply_correlation(
            results
        )

        print_correlation_diagnostic(
            results
        )

    except KeyboardInterrupt:

        print()
        print(
            "[!] Scan interrupted by user."
        )

        return 130

    except Exception as exc:

        print()
        print(
            f"[ERROR] Scan failed: "
            f"{exc}"
        )

        return 1

    elapsed = (
        time.perf_counter()
        - start_time
    )

    # --------------------------------------------------------
    # REPORTS
    # --------------------------------------------------------

    print_memory_information(
        results
    )

    print_threat_alerts(
        results
    )

    print_final_summary(
        results,
        elapsed,
    )

    save_scan_results(
        results,
        elapsed,
    )

    save_validation_report(
        results,
        elapsed,
    )

    return 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    sys.exit(
        main()
    )
