"""
PhantomTrace - Baseline Analysis

Detection Accuracy & False-Positive Reduction

Purpose:
- Classify processes against a known baseline.
- Identify trusted and suspicious executable locations.
- Avoid treating every unknown process as malicious.
- Produce structured baseline evidence for the threat scoring engine.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable


# ---------------------------------------------------------------------------
# Common Windows processes
# ---------------------------------------------------------------------------

COMMON_PROCESSES = {
    "system",
    "system idle process",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "spoolsv.exe",
    "taskhostw.exe",
    "sihost.exe",
    "ctfmon.exe",
    "runtimebroker.exe",
    "searchhost.exe",
    "searchindexer.exe",
    "startmenuexperiencehost.exe",
    "textinputhost.exe",
    "applicationframehost.exe",
    "conhost.exe",
    "dllhost.exe",
    "wmiprvse.exe",
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
    "brave.exe",
    "code.exe",
    "python.exe",
    "pythonw.exe",
    "powershell.exe",
    "cmd.exe",
}


# ---------------------------------------------------------------------------
# Trusted Windows locations
# ---------------------------------------------------------------------------

TRUSTED_DIRECTORIES = {
    os.path.normcase(os.path.normpath(r"C:\Windows")),
    os.path.normcase(os.path.normpath(r"C:\Windows\System32")),
    os.path.normcase(os.path.normpath(r"C:\Windows\SysWOW64")),
    os.path.normcase(os.path.normpath(r"C:\Program Files")),
    os.path.normcase(os.path.normpath(r"C:\Program Files (x86)")),
}


# ---------------------------------------------------------------------------
# Suspicious locations
# ---------------------------------------------------------------------------

SUSPICIOUS_DIRECTORY_NAMES = {
    "temp",
    "tmp",
    "appdata",
    "downloads",
    "desktop",
    "public",
}


def _normalize(value: str | None) -> str:
    """Normalize Windows path/process names."""
    if not value:
        return ""

    return os.path.normcase(
        os.path.normpath(str(value).strip())
    )


def _process_name(process: Dict[str, Any]) -> str:
    """Safely obtain a process name."""
    return str(
        process.get("name")
        or ""
    ).strip().lower()


def _process_path(process: Dict[str, Any]) -> str:
    """Safely obtain executable path."""
    return _normalize(
        process.get("exe")
        or process.get("path")
        or ""
    )


def _is_under_directory(path: str, directory: str) -> bool:
    """
    Return True when path is inside directory.

    Example:
        C:\\Windows\\System32\\cmd.exe
    is inside:
        C:\\Windows\\System32
    """
    if not path or not directory:
        return False

    try:
        common = os.path.commonpath([path, directory])
        return common == directory
    except ValueError:
        return False


def _is_trusted_path(path: str) -> bool:
    """Determine whether an executable is located in a trusted directory."""
    if not path:
        return False

    for directory in TRUSTED_DIRECTORIES:
        if _is_under_directory(path, directory):
            return True

    return False


def _is_suspicious_path(path: str) -> bool:
    """
    Detect executable paths containing commonly abused user/temp locations.

    This is an indicator only.
    A suspicious path does NOT automatically mean malware.
    """
    if not path:
        return False

    normalized = path.replace("/", "\\").lower()

    parts = {
        part.strip()
        for part in normalized.split("\\")
        if part.strip()
    }

    return bool(parts.intersection(SUSPICIOUS_DIRECTORY_NAMES))


def classify_baseline(process: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classify one process.

    Possible classifications:

        COMMON
        TRUSTED
        SUSPICIOUS_PATH
        PATH_UNAVAILABLE
        UNCLASSIFIED
    """

    name = _process_name(process)
    path = _process_path(process)

    result = {
        "classification": "UNCLASSIFIED",
        "is_common": False,
        "is_trusted_path": False,
        "is_suspicious_path": False,
        "path_available": bool(path),
        "evidence": [],
    }

    if name in COMMON_PROCESSES:
        result["is_common"] = True
        result["classification"] = "COMMON"
        result["evidence"].append(
            f"Process '{name}' is in the common-process baseline."
        )

    if not path:
        result["classification"] = "PATH_UNAVAILABLE"
        result["evidence"].append(
            "Executable path is unavailable."
        )
        return result

    if _is_suspicious_path(path):
        result["is_suspicious_path"] = True
        result["classification"] = "SUSPICIOUS_PATH"
        result["evidence"].append(
            f"Executable path is located in a commonly abused directory: {path}"
        )
        return result

    if _is_trusted_path(path):
        result["is_trusted_path"] = True

        if result["classification"] != "COMMON":
            result["classification"] = "TRUSTED"

        result["evidence"].append(
            f"Executable path is inside a trusted directory: {path}"
        )

    return result


def analyze_baseline(
    processes: Iterable[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Analyze the complete process list.

    Returns a structured baseline report suitable for threat scoring.
    """

    process_list = list(processes)

    findings = []

    common_count = 0
    unknown_count = 0
    trusted_count = 0
    suspicious_count = 0
    unavailable_count = 0

    for process in process_list:
        result = classify_baseline(process)

        classification = result["classification"]

        if result["is_common"]:
            common_count += 1

        if result["is_trusted_path"]:
            trusted_count += 1

        if result["is_suspicious_path"]:
            suspicious_count += 1

        if classification == "PATH_UNAVAILABLE":
            unavailable_count += 1

        if classification == "UNCLASSIFIED":
            unknown_count += 1

        if result["is_suspicious_path"]:
            findings.append(
                {
                    "pid": process.get("pid"),
                    "name": process.get("name"),
                    "exe": process.get("exe"),
                    "classification": classification,
                    "evidence": result["evidence"],
                }
            )

    return {
        "processes_analyzed": len(process_list),
        "common_processes": common_count,
        "unknown_processes": unknown_count,
        "trusted_paths": trusted_count,
        "suspicious_paths": suspicious_count,
        "path_unavailable": unavailable_count,
        "findings": findings,
        "finding_count": len(findings),
    }


def print_baseline_summary(report: Dict[str, Any]) -> None:
    """Print human-readable baseline summary."""

    print()
    print("=" * 70)
    print("PHANTOMTRACE - BASELINE SUMMARY")
    print("=" * 70)

    print(
        f"Processes analyzed : {report['processes_analyzed']}"
    )
    print(
        f"Common processes   : {report['common_processes']}"
    )
    print(
        f"Unknown processes  : {report['unknown_processes']}"
    )
    print(
        f"Trusted paths      : {report['trusted_paths']}"
    )
    print(
        f"Suspicious paths   : {report['suspicious_paths']}"
    )
    print(
        f"Path unavailable   : {report['path_unavailable']}"
    )

    print("=" * 70)
    print()
    print("=" * 100)
    print("PHANTOMTRACE - BASELINE REVIEW FINDINGS")
    print("=" * 100)

    if not report["findings"]:
        print("No baseline review findings.")
    else:
        for finding in report["findings"]:
            print()
            print(
                f"PID {finding.get('pid')} - "
                f"{finding.get('name')}"
            )
            print(
                f"Path: {finding.get('exe')}"
            )

            for evidence in finding.get("evidence", []):
                print(f"Evidence: {evidence}")

    print("=" * 100)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def self_test() -> None:
    """Basic baseline module test."""

    test_processes = [
        {
            "pid": 100,
            "name": "explorer.exe",
            "exe": r"C:\Windows\explorer.exe",
        },
        {
            "pid": 200,
            "name": "unknown.exe",
            "exe": r"C:\Users\Test\AppData\Local\Temp\unknown.exe",
        },
        {
            "pid": 300,
            "name": "example.exe",
            "exe": r"C:\Program Files\Example\example.exe",
        },
        {
            "pid": 400,
            "name": "unknown2.exe",
            "exe": None,
        },
    ]

    report = analyze_baseline(test_processes)

    assert report["processes_analyzed"] == 4
    assert report["common_processes"] == 1
    assert report["suspicious_paths"] == 1
    assert report["trusted_paths"] == 2
    assert report["path_unavailable"] == 1

    print("Baseline self-test: PASS")


if __name__ == "__main__":
    self_test()
