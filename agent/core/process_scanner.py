"""
PhantomTrace
Windows Process Scanner
PhantomTrace Windows Process Scanner

Purpose:
    Collect read-only Windows process information and connect
    each process to the PhantomTrace baseline engine.

This scanner:
    - Reads running processes
    - Collects process information
    - Checks common-process baseline
    - Checks trusted executable paths
    - Checks suspicious executable paths
    - Generates baseline evidence

IMPORTANT:
    This module is READ-ONLY.

    It does NOT:
        - terminate processes
        - delete files
        - quarantine files
        - modify processes
        - modify the Windows registry
"""


import psutil

from datetime import datetime

from .baseline import (
    analyze_baseline,
    generate_baseline_evidence,
)


# ============================================================
# PROCESS INFORMATION
# ============================================================

def get_process_info(process):
    """
    Collect useful information about a Windows process.

    The function also performs PhantomTrace baseline analysis.
    """

    try:

        with process.oneshot():

            # ------------------------------------------------
            # Basic process information
            # ------------------------------------------------

            pid = process.pid

            # ------------------------------------------------
            # Process name
            # ------------------------------------------------

            try:

                name = process.name()

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
            ):

                name = "Unknown"

            # ------------------------------------------------
            # Executable path
            # ------------------------------------------------

            try:

                exe = process.exe()

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
            ):

                exe = "Access Denied"

            # ------------------------------------------------
            # Command line
            # ------------------------------------------------

            try:

                cmdline = process.cmdline()

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
            ):

                cmdline = []

            # ------------------------------------------------
            # Username
            # ------------------------------------------------

            try:

                username = process.username()

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
            ):

                username = "Access Denied"

            # ------------------------------------------------
            # Parent PID
            # ------------------------------------------------

            try:

                parent_pid = process.ppid()

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
            ):

                parent_pid = None

            # ------------------------------------------------
            # Creation time
            # ------------------------------------------------

            try:

                create_time = process.create_time()

                created = datetime.fromtimestamp(
                    create_time
                ).isoformat()

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                OSError,
                ValueError,
            ):

                created = None

            # ------------------------------------------------
            # Memory information
            # ------------------------------------------------

            try:

                memory = process.memory_info()

                memory_rss = memory.rss
                memory_vms = memory.vms

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
            ):

                memory_rss = None
                memory_vms = None

            # ------------------------------------------------
            # CPU information
            # ------------------------------------------------

            try:

                cpu_percent = process.cpu_percent(
                    interval=0.1
                )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
            ):

                cpu_percent = None

            # =================================================
            # PHANTOMTRACE BASELINE ANALYSIS
            # =================================================

            # "Access Denied" is not an executable path.
            #
            # We therefore pass None to the baseline engine
            # rather than accidentally treating "Access Denied"
            # as a real Windows path.

            baseline_path = exe

            if (
                not baseline_path
                or baseline_path == "Access Denied"
            ):

                baseline_path = None

            # ------------------------------------------------
            # Run baseline analysis
            # ------------------------------------------------

            baseline = analyze_baseline(
                process_name=name,
                executable_path=baseline_path,
            )

            # ------------------------------------------------
            # Generate human-readable evidence
            # ------------------------------------------------

            baseline_evidence = generate_baseline_evidence(
                process_name=name,
                executable_path=baseline_path,
            )

            # =================================================
            # RETURN PROCESS RESULT
            # =================================================

            return {
                # --------------------------------------------
                # Original process information
                # --------------------------------------------

                "pid": pid,
                "name": name,
                "exe": exe,
                "cmdline": cmdline,
                "username": username,
                "parent_pid": parent_pid,
                "created": created,
                "memory_rss": memory_rss,
                "memory_vms": memory_vms,
                "cpu_percent": cpu_percent,

                # --------------------------------------------
                # Baseline information
                # --------------------------------------------

                "baseline": baseline,

                "baseline_evidence": baseline_evidence,
            }

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
    ):

        return None


# ============================================================
# PROCESS SCANNER
# ============================================================

def scan_processes():
    """
    Scan all currently running Windows processes.

    This is a READ-ONLY scan.
    """

    processes = []

    # --------------------------------------------------------
    # Request useful process attributes where possible.
    # --------------------------------------------------------

    for process in psutil.process_iter(
        [
            "pid",
            "name",
            "username",
            "ppid",
            "create_time",
        ]
    ):

        process_info = get_process_info(
            process
        )

        if process_info is not None:

            processes.append(
                process_info
            )

    return processes


# ============================================================
# BASELINE SUMMARY
# ============================================================

def summarize_baseline(processes):
    """
    Create a simple baseline summary.

    This is useful for the future web dashboard.
    """

    summary = {
        "total_processes": len(processes),
        "common_processes": 0,
        "unknown_processes": 0,
        "trusted_paths": 0,
        "suspicious_paths": 0,
        "path_unavailable": 0,
    }

    for process in processes:

        baseline = process.get(
            "baseline",
            {}
        )

        # ----------------------------------------------------
        # Common process
        # ----------------------------------------------------

        if baseline.get(
            "common_process",
            False,
        ):

            summary["common_processes"] += 1

        # ----------------------------------------------------
        # Unknown process
        # ----------------------------------------------------

        if baseline.get(
            "unknown_process",
            False,
        ):

            summary["unknown_processes"] += 1

        # ----------------------------------------------------
        # Trusted path
        # ----------------------------------------------------

        if baseline.get(
            "trusted_path",
            False,
        ):

            summary["trusted_paths"] += 1

        # ----------------------------------------------------
        # Suspicious path
        # ----------------------------------------------------

        if baseline.get(
            "suspicious_path",
            False,
        ):

            summary["suspicious_paths"] += 1

        # ----------------------------------------------------
        # Path unavailable
        # ----------------------------------------------------

        if not baseline.get(
            "path_available",
            False,
        ):

            summary["path_unavailable"] += 1

    return summary


# ============================================================
# PRINT PROCESS TABLE
# ============================================================

def print_processes(processes):
    """
    Print a readable process table.
    """

    print("\n" + "=" * 120)

    print(
        "PHANTOMTRACE - WINDOWS PROCESS SCANNER"
    )

    print("=" * 120)

    print(
        f"{'PID':<8}"
        f"{'NAME':<30}"
        f"{'PARENT':<10}"
        f"{'CPU %':<10}"
        f"{'BASELINE':<15}"
        f"{'PATH STATUS':<20}"
    )

    print("-" * 120)

    for process in processes:

        pid = process.get(
            "pid"
        )

        name = process.get(
            "name",
            "Unknown",
        )

        parent_pid = process.get(
            "parent_pid"
        )

        cpu = process.get(
            "cpu_percent"
        )

        baseline = process.get(
            "baseline",
            {}
        )

        # ----------------------------------------------------
        # Determine baseline display status
        # ----------------------------------------------------

        if baseline.get(
            "common_process",
            False,
        ):

            baseline_status = "COMMON"

        elif baseline.get(
            "unknown_process",
            False,
        ):

            baseline_status = "UNKNOWN"

        else:

            baseline_status = "UNKNOWN"

        # ----------------------------------------------------
        # Determine path status
        # ----------------------------------------------------

        if baseline.get(
            "suspicious_path",
            False,
        ):

            path_status = "REVIEW"

        elif baseline.get(
            "trusted_path",
            False,
        ):

            path_status = "TRUSTED"

        elif not baseline.get(
            "path_available",
            False,
        ):

            path_status = "UNAVAILABLE"

        else:

            path_status = "OTHER"

        # ----------------------------------------------------
        # Print row
        # ----------------------------------------------------

        print(
            f"{str(pid):<8}"
            f"{str(name)[:28]:<30}"
            f"{str(parent_pid):<10}"
            f"{str(cpu):<10}"
            f"{baseline_status:<15}"
            f"{path_status:<20}"
        )

    print("=" * 120)

    print(
        f"Total processes detected: "
        f"{len(processes)}"
    )

    print("=" * 120)


# ============================================================
# PRINT BASELINE SUMMARY
# ============================================================

def print_baseline_summary(processes):
    """
    Print PhantomTrace baseline statistics.
    """

    summary = summarize_baseline(
        processes
    )

    print("\n" + "=" * 70)

    print(
        "PHANTOMTRACE - BASELINE SUMMARY"
    )

    print("=" * 70)

    print(
        f"Processes analyzed : "
        f"{summary['total_processes']}"
    )

    print(
        f"Common processes   : "
        f"{summary['common_processes']}"
    )

    print(
        f"Unknown processes  : "
        f"{summary['unknown_processes']}"
    )

    print(
        f"Trusted paths      : "
        f"{summary['trusted_paths']}"
    )

    print(
        f"Suspicious paths   : "
        f"{summary['suspicious_paths']}"
    )

    print(
        f"Path unavailable   : "
        f"{summary['path_unavailable']}"
    )

    print("=" * 70)


# ============================================================
# PRINT BASELINE FINDINGS
# ============================================================

def print_baseline_findings(processes):
    """
    Print processes that deserve additional review.

    Important:
        These are NOT automatically malware.
    """

    findings = []

    for process in processes:

        baseline = process.get(
            "baseline",
            {}
        )

        # ----------------------------------------------------
        # Suspicious path
        # ----------------------------------------------------

        if baseline.get(
            "suspicious_path",
            False,
        ):

            findings.append(
                process
            )

        # ----------------------------------------------------
        # Unknown process
        # ----------------------------------------------------

        elif baseline.get(
            "unknown_process",
            False,
        ):

            findings.append(
                process
            )

    print("\n" + "=" * 100)

    print(
        "PHANTOMTRACE - BASELINE REVIEW FINDINGS"
    )

    print("=" * 100)

    if not findings:

        print(
            "No baseline review findings."
        )

        print("=" * 100)

        return

    for process in findings:

        print(
            f"\nProcess: "
            f"{process.get('name', 'Unknown')}"
        )

        print(
            f"PID: "
            f"{process.get('pid')}"
        )

        print(
            f"Path: "
            f"{process.get('exe')}"
        )

        baseline = process.get(
            "baseline",
            {}
        )

        print(
            f"Common process: "
            f"{baseline.get('common_process')}"
        )

        print(
            f"Trusted path: "
            f"{baseline.get('trusted_path')}"
        )

        print(
            f"Suspicious path: "
            f"{baseline.get('suspicious_path')}"
        )

        print("Evidence:")

        for evidence in process.get(
            "baseline_evidence",
            []
        ):

            print(
                f"  - {evidence}"
            )

    print("\n" + "=" * 100)

    print(
        f"Processes requiring baseline review: "
        f"{len(findings)}"
    )

    print("=" * 100)


# ============================================================
# MAIN
# ============================================================

def main():
    """
    Run the PhantomTrace read-only process scanner.
    """

    print(
        "\nStarting PhantomTrace..."
    )

    print(
        "Mode: READ-ONLY"
    )

    print(
        "Scanning Windows processes..."
    )

    processes = scan_processes()

    print_processes(
        processes
    )

    print_baseline_summary(
        processes
    )

    print_baseline_findings(
        processes
    )

    print(
        "\nPhantomTrace process scan completed."
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
