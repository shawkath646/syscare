"""
Winget Application Updater Engine for SysCare
Scans for outdated applications and handles one-click selective or bulk upgrades.
"""

import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple


@dataclass
class WingetPackage:
    name: str
    id: str
    current_version: str
    available_version: str
    source: str


class AppUpdater:
    def __init__(self):
        self._winget_path = shutil.which("winget")

    def is_available(self) -> bool:
        return self._winget_path is not None

    def get_available_updates(self, progress_callback: Optional[Callable[[str], None]] = None) -> List[WingetPackage]:
        """Runs winget upgrade to check for outdated installed software."""
        if not self.is_available():
            return []

        if progress_callback:
            progress_callback("Querying winget repository for software updates...")

        try:
            cmd = ["winget", "upgrade"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode != 0 and not res.stdout:
                return []

            lines = res.stdout.splitlines()
            sep_idx = -1
            for i, line in enumerate(lines):
                if line.strip().startswith("---"):
                    sep_idx = i
                    break

            if sep_idx == -1:
                return []

            updates: List[WingetPackage] = []
            for line in lines[sep_idx + 1:]:
                line = line.strip()
                if not line or "upgrades available" in line or "package(s)" in line:
                    break
                parts = line.split()
                if len(parts) >= 5:
                    source = parts[-1]
                    available = parts[-2]
                    current = parts[-3]
                    pkg_id = parts[-4]
                    name = " ".join(parts[:-4])
                    updates.append(WingetPackage(
                        name=name,
                        id=pkg_id,
                        current_version=current,
                        available_version=available,
                        source=source
                    ))

            return updates
        except Exception:
            return []

    def upgrade_all(self, interactive: bool = False, progress_callback: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
        """Upgrades all outdated packages using winget."""
        if not self.is_available():
            return False, "Winget is not installed or not in PATH."

        if progress_callback:
            progress_callback("Running winget upgrade --all...")

        cmd = ["winget", "upgrade", "--all", "--accept-source-agreements", "--accept-package-agreements"]
        if not interactive:
            cmd.append("--silent")

        try:
            # Run interactively so the user sees download/install progress
            res = subprocess.run(cmd, check=False)
            if res.returncode == 0:
                return True, "All applications successfully updated."
            else:
                return False, f"Winget completed with return code {res.returncode}."
        except Exception as e:
            return False, f"Failed to execute winget: {e}"

    def upgrade_package(self, package_id: str, interactive: bool = False) -> Tuple[bool, str]:
        """Upgrades a single package by its ID."""
        if not self.is_available():
            return False, "Winget is not available."

        cmd = ["winget", "upgrade", "--id", package_id, "--accept-source-agreements", "--accept-package-agreements"]
        if not interactive:
            cmd.append("--silent")

        try:
            res = subprocess.run(cmd, check=False)
            if res.returncode == 0:
                return True, f"Successfully updated {package_id}."
            else:
                return False, f"Failed to update {package_id} (code {res.returncode})."
        except Exception as e:
            return False, f"Execution error: {e}"
