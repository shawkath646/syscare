"""
Smart Process & Resource Health Guardian for SysCare
AI-style intelligent inspection of running processes to detect suspicious activities,
disguised binaries, and background resource hogs consuming excessive RAM/CPU.
"""

import csv
import io
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from core.console import format_bytes


@dataclass
class FlaggedProcess:
    name: str
    pid: int
    mem_bytes: int
    mem_str: str
    cpu_time: str
    user: str
    window_title: str
    path: str
    severity: str          # "CRITICAL", "WARNING", "INFO"
    diagnosis: str
    recommendation: str


@dataclass
class GuardianReport:
    total_processes_scanned: int = 0
    flagged_processes: List[FlaggedProcess] = field(default_factory=list)
    total_hog_memory_bytes: int = 0
    system_health_status: str = "OPTIMAL"  # "OPTIMAL", "MODERATE", "ALERT"


class ProcessGuardian:
    # Essential Windows core processes that should never be flagged as hogs or killed
    SYSTEM_CRITICAL_PROCESSES = {
        "system", "system idle process", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe", "winlogon.exe",
        "dwm.exe", "explorer.exe", "sihost.exe", "taskhostw.exe", "searchindexer.exe",
        "registry", "memory compression", "antigravity.exe", "syscare"
    }

    # Core system binaries that must ONLY run from C:\Windows\System32
    SYSTEM32_ONLY_BINARIES = {
        "svchost.exe", "csrss.exe", "lsass.exe", "services.exe", "smss.exe",
        "wininit.exe", "winlogon.exe", "conhost.exe"
    }

    @staticmethod
    def _get_process_path(pid: int) -> str:
        """Queries process executable path in microseconds using Windows kernel32 API."""
        try:
            import ctypes
            # PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
            if not handle:
                return ""
            buf = ctypes.create_unicode_buffer(1024)
            size = ctypes.c_ulong(1024)
            success = ctypes.windll.kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size))
            ctypes.windll.kernel32.CloseHandle(handle)
            if success:
                return buf.value
        except Exception:
            pass
        return ""

    def scan(self, progress_callback: Optional[Callable[[str], None]] = None) -> GuardianReport:
        """Inspects all running processes using smart AI-style behavioral heuristics."""
        report = GuardianReport()

        if progress_callback:
            progress_callback("Inspecting running processes and memory footprint...")

        try:
            cmd = ["tasklist", "/fo", "csv"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode != 0:
                return report

            reader = csv.reader(io.StringIO(res.stdout))
            header = next(reader, None)

            temp_pattern = re.compile(r'(\\temp\\|\\local\\temp\\|\\appdata\\local\\temp\\)', re.IGNORECASE)

            for row in reader:
                if len(row) < 5:
                    continue

                report.total_processes_scanned += 1
                name = row[0].strip()
                name_lower = name.lower()

                try:
                    pid = int(row[1].strip())
                except Exception:
                    continue

                # Parse memory (e.g. "154,248 K" -> bytes)
                mem_raw = row[4].replace("K", "").replace("M", "").replace(",", "").replace(".", "").strip()
                try:
                    mem_bytes = int(mem_raw) * 1024
                except Exception:
                    mem_bytes = 0

                is_system_proc = name_lower in self.SYSTEM_CRITICAL_PROCESSES

                # Query path only when relevant (saves massive overhead)
                p_path = ""
                if name_lower in self.SYSTEM32_ONLY_BINARIES or mem_bytes > 300 * 1024 * 1024 or not is_system_proc:
                    p_path = self._get_process_path(pid)

                flagged = False
                severity = "NORMAL"
                diagnosis = ""
                recommendation = ""

                # Heuristic 1: Disguised system binary check
                if name_lower in self.SYSTEM32_ONLY_BINARIES and p_path:
                    norm_path = p_path.lower()
                    if "system32" not in norm_path and "syswow64" not in norm_path:
                        flagged = True
                        severity = "CRITICAL"
                        diagnosis = f"Disguised binary! '{name}' is running from non-system location: {p_path}"
                        recommendation = "High risk: Terminate immediately and inspect file."

                # Heuristic 2: Running from Temp directory
                if not flagged and p_path and temp_pattern.search(p_path):
                    flagged = True
                    severity = "CRITICAL"
                    diagnosis = f"Process running directly from Temp directory ({p_path})"
                    recommendation = "Terminating will prevent unwanted background persistence."

                # Heuristic 3: Background resource hog (>450 MB RAM without active visible window)
                if not flagged and not is_system_proc and mem_bytes > 450 * 1024 * 1024:
                    if window_title in ("N/A", "", "Default IME", "MSCTFIME UI"):
                        flagged = True
                        severity = "WARNING"
                        diagnosis = f"Background process consuming {format_bytes(mem_bytes)} RAM without an active user window."
                        recommendation = "Terminate if not in use to reclaim system memory."

                # Heuristic 4: Lingering background developer runtime (>200 MB RAM)
                if not flagged and name_lower in ("node.exe", "python.exe", "ruby.exe", "git.exe") and mem_bytes > 200 * 1024 * 1024:
                    if window_title in ("N/A", ""):
                        flagged = True
                        severity = "INFO"
                        diagnosis = f"Lingering background {name} runtime consuming {format_bytes(mem_bytes)} RAM."
                        recommendation = "Safe to close if you are not currently running a background script."

                if flagged:
                    report.flagged_processes.append(FlaggedProcess(
                        name=name,
                        pid=pid,
                        mem_bytes=mem_bytes,
                        mem_str=format_bytes(mem_bytes),
                        cpu_time=cpu_time,
                        user=user,
                        window_title=window_title,
                        path=p_path,
                        severity=severity,
                        diagnosis=diagnosis,
                        recommendation=recommendation
                    ))
                    report.total_hog_memory_bytes += mem_bytes

            # Calculate overall health status
            has_critical = any(p.severity == "CRITICAL" for p in report.flagged_processes)
            has_warning = any(p.severity == "WARNING" for p in report.flagged_processes)

            if has_critical:
                report.system_health_status = "ALERT"
            elif has_warning:
                report.system_health_status = "MODERATE"
            else:
                report.system_health_status = "OPTIMAL"

        except Exception as e:
            pass

        return report

    def terminate_process(self, pid: int) -> Tuple[bool, str]:
        """Terminates a flagged rogue process by PID."""
        try:
            res = subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, text=True, check=False)
            if res.returncode == 0:
                return True, f"Successfully terminated PID {pid}."
            return False, res.stderr.strip() or res.stdout.strip()
        except Exception as e:
            return False, f"Execution error: {e}"
