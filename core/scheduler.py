"""
Weekly Checker & Windows Task Scheduler Integration for SysCare
Allows scheduling automated weekly system care using Windows schtasks.
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple


class WeeklyScheduler:
    TASK_NAME = "SysCare_WeeklyCheck"

    def __init__(self, script_root: Path):
        self.script_root = script_root
        self.quick_bat = self.script_root / "syscare_quick.bat"
        self.main_py = self.script_root / "main.py"

    def get_status(self) -> Optional[Dict[str, str]]:
        """Queries Windows Task Scheduler for the SysCare task status."""
        try:
            cmd = ["schtasks.exe", "/query", "/tn", self.TASK_NAME, "/fo", "LIST", "/v"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode != 0:
                return None

            info: Dict[str, str] = {}
            for line in res.stdout.splitlines():
                if ":" in line:
                    parts = line.split(":", 1)
                    key = parts[0].strip()
                    val = parts[1].strip()
                    if key in ("TaskName", "Next Run Time", "Status", "Last Run Time", "Last Result", "Schedule"):
                        info[key] = val
            return info if info else {"Status": "Registered"}
        except Exception:
            return None

    def schedule_weekly(self, day: str = "SUN", time_str: str = "10:00") -> Tuple[bool, str]:
        """
        Creates or updates a weekly task in Windows Task Scheduler.
        Runs python main.py --all --yes or syscare.exe --all --yes
        """
        # Target command
        if getattr(sys, "frozen", False):
            action_cmd = f'"{sys.executable}" --all --yes'
        else:
            python_exe = sys.executable
            action_cmd = f'"{python_exe}" "{self.main_py}" --all --yes'

        cmd = [
            "schtasks.exe", "/create",
            "/tn", self.TASK_NAME,
            "/tr", action_cmd,
            "/sc", "WEEKLY",
            "/d", day.upper(),
            "/st", time_str,
            "/f"  # Force overwrite if exists
        ]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode == 0:
                return True, f"Weekly check scheduled every {day.upper()} at {time_str}."
            else:
                err_msg = res.stderr.strip() or res.stdout.strip()
                return False, f"Failed to create scheduled task: {err_msg}"
        except Exception as e:
            return False, f"Error calling schtasks: {e}"

    def remove_schedule(self) -> Tuple[bool, str]:
        """Removes the weekly scheduled task from Windows Task Scheduler."""
        cmd = ["schtasks.exe", "/delete", "/tn", self.TASK_NAME, "/f"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode == 0:
                return True, "Weekly scheduled check successfully removed."
            else:
                err_msg = res.stderr.strip() or res.stdout.strip()
                return False, f"Could not remove task: {err_msg}"
        except Exception as e:
            return False, f"Error calling schtasks: {e}"
