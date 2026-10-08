"""
PhantomTrace
PhantomTrace Windows Memory Scanner
Memory Scanner

Defensive Windows process-memory scanner.

Features:
    - Enumerates running processes
    - Opens accessible processes with read/query permissions
    - Walks virtual memory regions using VirtualQueryEx
    - Detects executable + writable memory
    - Detects private executable memory
    - Detects guarded executable memory
    - Produces normalized results for Threat Scoring

Safety:
    This scanner is READ-ONLY.
    It does not inject, modify, or execute code in other processes.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import platform
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

import psutil


# ============================================================
# WINDOWS API CONSTANTS
# ============================================================

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000

MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x100000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08

PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400


# ============================================================
# MEMORY PROTECTION NAMES
# ============================================================

PROTECTION_NAMES = {
    PAGE_NOACCESS: "NOACCESS",
    PAGE_READONLY: "READONLY",
    PAGE_READWRITE: "READWRITE",
    PAGE_WRITECOPY: "WRITECOPY",
    PAGE_EXECUTE: "EXECUTE",
    PAGE_EXECUTE_READ: "EXECUTE_READ",
    PAGE_EXECUTE_READWRITE: "EXECUTE_READWRITE",
    PAGE_EXECUTE_WRITECOPY: "EXECUTE_WRITECOPY",
}


# ============================================================
# MEMORY BASIC INFORMATION
# ============================================================

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """
    Windows MEMORY_BASIC_INFORMATION structure.

    Used by VirtualQueryEx().
    """

    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


# ============================================================
# MEMORY REGION RESULT
# ============================================================

@dataclass
class MemoryRegion:
    """
    Represents one committed virtual-memory region.
    """

    base_address: int
    region_size: int
    state: int
    protection: int
    protection_name: str
    memory_type: int
    memory_type_name: str
    suspicious: bool
    indicators: List[str]


# ============================================================
# PROCESS MEMORY RESULT
# ============================================================

@dataclass
class ProcessMemoryResult:
    """
    Normalized memory scan result for one process.
    """

    pid: int
    name: str
    executable: str
    status: str

    total_regions: int
    executable_regions: int
    writable_executable_regions: int
    private_executable_regions: int
    suspicious_regions: int

    indicators: List[str]
    regions: List[MemoryRegion]

    error: Optional[str] = None

    @property
    def evidence_strength(self) -> str:
        """
        Classify memory evidence without declaring malware.

        NONE     = no indicators
        WEAK     = private executable memory only
        MODERATE = executable + writable memory
        STRONG   = private RWX or multiple strong indicators
        """

        indicators = set(
            self.indicators or []
        )

        if not indicators:
            return "NONE"

        if "PRIVATE_RWX_MEMORY" in indicators:
            return "STRONG"

        if (
            "EXECUTABLE_WRITABLE_MEMORY" in indicators
            and "GUARDED_EXECUTABLE_MEMORY" in indicators
        ):
            return "STRONG"

        if "EXECUTABLE_WRITABLE_MEMORY" in indicators:
            return "MODERATE"

        if "PRIVATE_EXECUTABLE_MEMORY" in indicators:
            return "WEAK"

        return "WEAK"

    @property
    def threat_score(self) -> int:
        """
        Memory-specific evidence score.

        This is NOT the final PhantomTrace threat score.

        The final threat score should combine this evidence
        with behavioral and process indicators.
        """

        score = 0

        indicators = set(
            self.indicators or []
        )

        # Memory-only evidence is deliberately conservative.
        if "PRIVATE_EXECUTABLE_MEMORY" in indicators:
            score += 10

        if "EXECUTABLE_WRITABLE_MEMORY" in indicators:
            score += 15

        if "GUARDED_EXECUTABLE_MEMORY" in indicators:
            score += 5

        # Stronger combination.
        if "PRIVATE_RWX_MEMORY" in indicators:
            score += 25

        # Region count is only contextual evidence.
        if self.suspicious_regions >= 5:
            score += 5

        if self.suspicious_regions >= 20:
            score += 5

        return min(score, 60)

    def to_dict(self) -> Dict:
        """
        Convert result to a normal dictionary.
        """

        data = asdict(self)

        data["threat_score"] = self.threat_score

        data["evidence_strength"] = (
            self.evidence_strength
        )

        return data


# ============================================================
# WINDOWS MEMORY SCANNER
# ============================================================

class WindowsMemoryScanner:
    """
    Read-only Windows process memory scanner.
    """

    def __init__(
        self,
        max_regions_per_process: int = 10000,
        scan_all_processes: bool = True,
    ):
        self.max_regions_per_process = max_regions_per_process

        # IMPORTANT:
        # Do NOT call this self.scan_all_processes because
        # scan_all_processes() is also a class method.
        self.scan_all_processes_enabled = scan_all_processes

        # ----------------------------------------------------
        # Load kernel32
        # ----------------------------------------------------

        self.kernel32 = ctypes.WinDLL(
            "kernel32",
            use_last_error=True,
        )

        # ----------------------------------------------------
        # OpenProcess
        # ----------------------------------------------------

        self.kernel32.OpenProcess.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]

        self.kernel32.OpenProcess.restype = wintypes.HANDLE

        # ----------------------------------------------------
        # VirtualQueryEx
        # ----------------------------------------------------

        self.kernel32.VirtualQueryEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(MEMORY_BASIC_INFORMATION),
            ctypes.c_size_t,
        ]

        self.kernel32.VirtualQueryEx.restype = ctypes.c_size_t

        # ----------------------------------------------------
        # CloseHandle
        # ----------------------------------------------------

        self.kernel32.CloseHandle.argtypes = [
            wintypes.HANDLE
        ]

        self.kernel32.CloseHandle.restype = wintypes.BOOL

    # ========================================================
    # PROCESS HELPERS
    # ========================================================

    @staticmethod
    def get_process_executable(
        process: psutil.Process,
    ) -> str:
        """
        Safely retrieve process executable path.
        """

        try:
            return process.exe()

        except (
            psutil.AccessDenied,
            psutil.NoSuchProcess,
        ):
            return ""

        except Exception:
            return ""

    # --------------------------------------------------------

    @staticmethod
    def get_process_name(
        process: psutil.Process,
    ) -> str:
        """
        Safely retrieve process name.
        """

        try:
            return process.name()

        except (
            psutil.AccessDenied,
            psutil.NoSuchProcess,
        ):
            return "Unknown"

        except Exception:
            return "Unknown"

    # ========================================================
    # MEMORY CLASSIFICATION
    # ========================================================

    @staticmethod
    def protection_name(
        protection: int,
    ) -> str:
        """
        Convert Windows memory protection flags to a readable name.
        """

        base_protection = protection & 0xFF

        return PROTECTION_NAMES.get(
            base_protection,
            f"UNKNOWN(0x{base_protection:X})",
        )

    # --------------------------------------------------------

    @staticmethod
    def memory_type_name(
        memory_type: int,
    ) -> str:
        """
        Convert memory type to readable name.
        """

        if memory_type == MEM_IMAGE:
            return "IMAGE"

        if memory_type == MEM_MAPPED:
            return "MAPPED"

        if memory_type == MEM_PRIVATE:
            return "PRIVATE"

        return f"UNKNOWN(0x{memory_type:X})"

    # --------------------------------------------------------

    @staticmethod
    def is_executable(
        protection: int,
    ) -> bool:
        """
        Determine whether memory is executable.
        """

        base_protection = protection & 0xFF

        return base_protection in {
            PAGE_EXECUTE,
            PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY,
        }

    # --------------------------------------------------------

    @staticmethod
    def is_writable(
        protection: int,
    ) -> bool:
        """
        Determine whether memory is writable.
        """

        base_protection = protection & 0xFF

        return base_protection in {
            PAGE_READWRITE,
            PAGE_WRITECOPY,
            PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY,
        }

    # --------------------------------------------------------

    @staticmethod
    def is_guarded(
        protection: int,
    ) -> bool:
        """
        Determine whether memory has PAGE_GUARD.
        """

        return bool(
            protection & PAGE_GUARD
        )

    # ========================================================
    # REGION ANALYSIS
    # ========================================================

    def analyze_region(
        self,
        mbi: MEMORY_BASIC_INFORMATION,
    ) -> MemoryRegion:
        """
        Analyze one Windows virtual-memory region.

        Memory scanning:
        - Executable/private memory is contextual evidence.
        - RWX is stronger evidence.
        - A region is not marked suspicious merely because it
          is executable or private.
        """

        protection = int(mbi.Protect)
        memory_type = int(mbi.Type)
        state = int(mbi.State)

        indicators: List[str] = []

        executable = self.is_executable(
            protection
        )

        writable = self.is_writable(
            protection
        )

        # Executable + writable memory.
        if executable and writable:
            indicators.append(
                "EXECUTABLE_WRITABLE_MEMORY"
            )

        # Private executable memory.
        #
        # Common in browsers, Electron/JIT runtimes and other
        # legitimate applications. Keep as weak contextual
        # evidence rather than marking the region suspicious.
        if (
            executable
            and memory_type == MEM_PRIVATE
        ):
            indicators.append(
                "PRIVATE_EXECUTABLE_MEMORY"
            )

        # Guarded executable memory.
        if (
            executable
            and self.is_guarded(protection)
        ):
            indicators.append(
                "GUARDED_EXECUTABLE_MEMORY"
            )

        # Private RWX is a stronger combination.
        if (
            executable
            and writable
            and memory_type == MEM_PRIVATE
        ):
            indicators.append(
                "PRIVATE_RWX_MEMORY"
            )

        # Only stronger combinations become a suspicious region.
        strong_memory_indicator = (
            "PRIVATE_RWX_MEMORY" in indicators
            or (
                "EXECUTABLE_WRITABLE_MEMORY" in indicators
                and "GUARDED_EXECUTABLE_MEMORY" in indicators
            )
        )

        suspicious = strong_memory_indicator

        return MemoryRegion(
            base_address=int(
                mbi.BaseAddress or 0
            ),
            region_size=int(
                mbi.RegionSize
            ),
            state=state,
            protection=protection,
            protection_name=self.protection_name(
                protection
            ),
            memory_type=memory_type,
            memory_type_name=self.memory_type_name(
                memory_type
            ),
            suspicious=suspicious,
            indicators=indicators,
        )

    # ========================================================
    # OPEN PROCESS
    # ========================================================

    def open_process(
        self,
        pid: int,
    ):
        """
        Open a process with query/read access.
        """

        access = (
            PROCESS_QUERY_INFORMATION
            | PROCESS_VM_READ
        )

        handle = self.kernel32.OpenProcess(
            access,
            False,
            pid,
        )

        if not handle:

            error_code = ctypes.get_last_error()

            raise PermissionError(
                f"OpenProcess failed for PID {pid}. "
                f"Windows error: {error_code}"
            )

        return handle

    # ========================================================
    # SCAN ONE PROCESS
    # ========================================================

    def scan_process(
        self,
        pid: int,
    ) -> ProcessMemoryResult:
        """
        Scan the virtual memory of one process.
        """

        # ----------------------------------------------------
        # Get process information
        # ----------------------------------------------------

        try:

            process = psutil.Process(pid)

            name = self.get_process_name(
                process
            )

            executable = self.get_process_executable(
                process
            )

        except psutil.NoSuchProcess:

            return ProcessMemoryResult(
                pid=pid,
                name="Unknown",
                executable="",
                status="terminated",
                total_regions=0,
                executable_regions=0,
                writable_executable_regions=0,
                private_executable_regions=0,
                suspicious_regions=0,
                indicators=[],
                regions=[],
            )

        except Exception as exc:

            return ProcessMemoryResult(
                pid=pid,
                name="Unknown",
                executable="",
                status="error",
                total_regions=0,
                executable_regions=0,
                writable_executable_regions=0,
                private_executable_regions=0,
                suspicious_regions=0,
                indicators=[],
                regions=[],
                error=str(exc),
            )

        # ----------------------------------------------------
        # Open process
        # ----------------------------------------------------

        try:

            handle = self.open_process(
                pid
            )

        except (
            PermissionError,
            OSError,
        ) as exc:

            return ProcessMemoryResult(
                pid=pid,
                name=name,
                executable=executable,
                status="access_denied",
                total_regions=0,
                executable_regions=0,
                writable_executable_regions=0,
                private_executable_regions=0,
                suspicious_regions=0,
                indicators=[
                    "MEMORY_ACCESS_DENIED"
                ],
                regions=[],
                error=str(exc),
            )

        # ----------------------------------------------------
        # Scan memory
        # ----------------------------------------------------

        regions: List[MemoryRegion] = []

        executable_regions = 0

        writable_executable_regions = 0

        private_executable_regions = 0

        suspicious_regions = 0

        address = 0

        try:

            while (
                len(regions)
                < self.max_regions_per_process
            ):

                mbi = MEMORY_BASIC_INFORMATION()

                result = self.kernel32.VirtualQueryEx(
                    handle,
                    ctypes.c_void_p(address),
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi),
                )

                # ------------------------------------------------
                # VirtualQueryEx failed/end of address space
                # ------------------------------------------------

                if result == 0:
                    break

                region = self.analyze_region(
                    mbi
                )

                # ------------------------------------------------
                # Only analyze committed memory
                # ------------------------------------------------

                if region.state == MEM_COMMIT:

                    regions.append(region)

                    # --------------------------------------------
                    # Executable
                    # --------------------------------------------

                    if self.is_executable(
                        region.protection
                    ):

                        executable_regions += 1

                    # --------------------------------------------
                    # Executable + writable
                    # --------------------------------------------

                    if (
                        self.is_executable(
                            region.protection
                        )
                        and self.is_writable(
                            region.protection
                        )
                    ):

                        writable_executable_regions += 1

                    # --------------------------------------------
                    # Private executable
                    # --------------------------------------------

                    if (
                        self.is_executable(
                            region.protection
                        )
                        and region.memory_type
                        == MEM_PRIVATE
                    ):

                        private_executable_regions += 1

                    # --------------------------------------------
                    # Suspicious
                    # --------------------------------------------

                    if region.suspicious:

                        suspicious_regions += 1

                # ------------------------------------------------
                # Calculate next memory address
                # ------------------------------------------------

                current_base = (
                    region.base_address
                )

                current_size = max(
                    region.region_size,
                    1,
                )

                next_address = (
                    current_base
                    + current_size
                )

                # ------------------------------------------------
                # Protect against infinite loop
                # ------------------------------------------------

                if next_address <= address:
                    break

                address = next_address

                # ------------------------------------------------
                # Protect against 64-bit overflow
                # ------------------------------------------------

                if address >= (
                    1 << 63
                ):

                    break

        finally:

            self.kernel32.CloseHandle(
                handle
            )

        # ====================================================
        # PROCESS INDICATORS
        # ====================================================

        indicators: List[str] = []

        if writable_executable_regions > 0:

            indicators.append(
                "EXECUTABLE_WRITABLE_MEMORY"
            )

        if private_executable_regions > 0:

            indicators.append(
                "PRIVATE_EXECUTABLE_MEMORY"
            )

        if suspicious_regions > 0:

            indicators.append(
                "SUSPICIOUS_MEMORY_REGION"
            )

        # ====================================================
        # RESULT
        # ====================================================

        return ProcessMemoryResult(
            pid=pid,
            name=name,
            executable=executable,
            status="scanned",

            total_regions=len(
                regions
            ),

            executable_regions=(
                executable_regions
            ),

            writable_executable_regions=(
                writable_executable_regions
            ),

            private_executable_regions=(
                private_executable_regions
            ),

            suspicious_regions=(
                suspicious_regions
            ),

            indicators=indicators,

            regions=regions,
        )

    # ========================================================
    # SCAN ALL PROCESSES
    # ========================================================

    def scan_all_processes(
        self,
    ) -> List[ProcessMemoryResult]:
        """
        Scan all currently running processes.
        """

        results: List[
            ProcessMemoryResult
        ] = []

        # ----------------------------------------------------
        # Enumerate processes
        # ----------------------------------------------------

        for process in psutil.process_iter(
            ["pid", "name"]
        ):

            try:

                pid = process.info["pid"]

                result = self.scan_process(
                    pid
                )

                results.append(
                    result
                )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):

                continue

            except Exception as exc:

                results.append(
                    ProcessMemoryResult(
                        pid=process.info.get(
                            "pid",
                            -1,
                        ),

                        name=process.info.get(
                            "name",
                            "Unknown",
                        ),

                        executable="",

                        status="error",

                        total_regions=0,

                        executable_regions=0,

                        writable_executable_regions=0,

                        private_executable_regions=0,

                        suspicious_regions=0,

                        indicators=[],

                        regions=[],

                        error=str(exc),
                    )
                )

        return results


# ============================================================
# PUBLIC API
# ============================================================

def scan_process_memory(
    pid: int,
) -> Dict:
    """
    Scan a single process and return a dictionary.
    """

    # --------------------------------------------------------
    # Platform check
    # --------------------------------------------------------

    if platform.system() != "Windows":

        return {
            "status": "unsupported",
            "pid": pid,
            "error": (
                "PhantomTrace memory scanning "
                "currently requires Windows."
            ),
        }

    # --------------------------------------------------------
    # Scanner
    # --------------------------------------------------------

    scanner = WindowsMemoryScanner()

    result = scanner.scan_process(
        pid
    )

    return result.to_dict()


# ============================================================

def scan_all_memory() -> List[Dict]:
    """
    Scan all accessible Windows processes.
    """

    # --------------------------------------------------------
    # Platform check
    # --------------------------------------------------------

    if platform.system() != "Windows":

        return [
            {
                "status": "unsupported",
                "error": (
                    "PhantomTrace memory scanning "
                    "currently requires Windows."
                ),
            }
        ]

    # --------------------------------------------------------
    # Scanner
    # --------------------------------------------------------

    scanner = WindowsMemoryScanner()

    results = scanner.scan_all_processes()

    return [
        result.to_dict()
        for result in results
    ]


# ============================================================
# MEMORY SUMMARY
# ============================================================

def summarize_memory_results(
    results: List[Dict],
) -> Dict:
    """
    Convert raw memory results into a compact summary.
    """

    summary = {
        "total_processes": len(
            results
        ),

        "scanned": 0,

        "access_denied": 0,

        "errors": 0,

        "unsupported": 0,

        "suspicious_processes": 0,

        "suspicious_regions": 0,

        "rwx_processes": 0,

        "private_executable_processes": 0,

        "alerts": [],
    }

    # --------------------------------------------------------
    # Process each result
    # --------------------------------------------------------

    for result in results:

        status = result.get(
            "status"
        )

        # ----------------------------------------------------
        # Status
        # ----------------------------------------------------

        if status == "scanned":

            summary["scanned"] += 1

        elif status == "access_denied":

            summary["access_denied"] += 1

        elif status == "unsupported":

            summary["unsupported"] += 1

        elif status == "error":

            summary["errors"] += 1

        # ----------------------------------------------------
        # Suspicious regions
        # ----------------------------------------------------

        suspicious_regions = result.get(
            "suspicious_regions",
            0,
        )

        summary[
            "suspicious_regions"
        ] += suspicious_regions

        # ----------------------------------------------------
        # Suspicious process
        # ----------------------------------------------------

        if suspicious_regions > 0:

            summary[
                "suspicious_processes"
            ] += 1

        # ----------------------------------------------------
        # RWX
        # ----------------------------------------------------

        if result.get(
            "writable_executable_regions",
            0,
        ) > 0:

            summary[
                "rwx_processes"
            ] += 1

        # ----------------------------------------------------
        # Private executable
        # ----------------------------------------------------

        if result.get(
            "private_executable_regions",
            0,
        ) > 0:

            summary[
                "private_executable_processes"
            ] += 1

        # ----------------------------------------------------
        # Alerts
        # ----------------------------------------------------

        if result.get(
            "indicators"
        ):

            summary[
                "alerts"
            ].append(
                {
                    "pid": result.get(
                        "pid"
                    ),

                    "process": result.get(
                        "name",
                        "Unknown",
                    ),

                    "indicators": result.get(
                        "indicators",
                        [],
                    ),

                    "threat_score": result.get(
                        "threat_score",
                        0,
                    ),
                }
            )

    return summary


# ============================================================
# PRINT SUMMARY
# ============================================================

def print_memory_summary(
    summary: Dict,
) -> None:
    """
    Print a clean PhantomTrace memory summary.
    """

    print()

    print(
        "=" * 60
    )

    print(
        "          PHANTOMTRACE MEMORY SCANNER"
    )

    print(
        "=" * 60
    )

    print()

    print(
        f"Total Processes      : "
        f"{summary['total_processes']}"
    )

    print(
        f"Scanned              : "
        f"{summary['scanned']}"
    )

    print(
        f"Access Denied        : "
        f"{summary['access_denied']}"
    )

    print(
        f"Errors               : "
        f"{summary['errors']}"
    )

    print(
        f"Suspicious Processes : "
        f"{summary['suspicious_processes']}"
    )

    print(
        f"Suspicious Regions   : "
        f"{summary['suspicious_regions']}"
    )

    print(
        f"RWX Processes        : "
        f"{summary['rwx_processes']}"
    )

    print(
        f"Private Executable   : "
        f"{summary['private_executable_processes']}"
    )

    print()

    print(
        "-" * 60
    )

    print(
        "MEMORY ALERTS"
    )

    print(
        "-" * 60
    )

    # --------------------------------------------------------
    # No alerts
    # --------------------------------------------------------

    if not summary["alerts"]:

        print(
            "No suspicious memory indicators detected."
        )

    # --------------------------------------------------------
    # Alerts
    # --------------------------------------------------------

    else:

        for alert in summary[
            "alerts"
        ]:

            print()

            print(
                f"PID       : "
                f"{alert['pid']}"
            )

            print(
                f"Process   : "
                f"{alert['process']}"
            )

            print(
                f"Indicators: "
                f"{', '.join(alert['indicators'])}"
            )

            print(
                f"Score     : "
                f"{alert['threat_score']}"
            )

    print()

    print(
        "=" * 60
    )

    print(
        "Memory scan complete."
    )

    print(
        "=" * 60
    )


# ============================================================
# COMMAND-LINE ENTRY POINT
# ============================================================

def main():
    """
    Run PhantomTrace memory scanner from command line.
    """

    # --------------------------------------------------------
    # Windows check
    # --------------------------------------------------------

    if platform.system() != "Windows":

        print()

        print(
            "[!] PhantomTrace memory scanner "
            "requires Windows."
        )

        return

    # --------------------------------------------------------
    # Start
    # --------------------------------------------------------

    print()

    print(
        "=" * 60
    )

    print(
        "          PHANTOMTRACE MEMORY SCANNER"
    )

    print(
        "=" * 60
    )

    print()

    print(
        "Scanning process memory..."
    )

    print(
        "This may require Administrator privileges."
    )

    print()

    # --------------------------------------------------------
    # Scan
    # --------------------------------------------------------

    results = scan_all_memory()

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    summary = summarize_memory_results(
        results
    )

    # --------------------------------------------------------
    # Print
    # --------------------------------------------------------

    print_memory_summary(
        summary
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    main()
