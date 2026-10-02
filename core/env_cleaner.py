"""
Environment Variable Cleaner for SysCare
Detects and removes stale PATH entries (pointing to deleted/non-existent directories)
and duplicate entries from both User and System PATH environment variables.
Enforces registry backup before making modifications and broadcasts WM_SETTINGCHANGE.
"""

import ctypes
import os
import winreg
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from core.safety import RegistryBackupItem, RegistryBackupManager


@dataclass
class PathEntry:
    original: str
    expanded: str
    scope: str  # "User" or "System"
    is_valid: bool
    is_duplicate: bool
    reason: str = ""


@dataclass
class EnvScanReport:
    entries: List[PathEntry] = field(default_factory=list)
    user_total: int = 0
    system_total: int = 0
    stale_count: int = 0
    duplicate_count: int = 0

    @property
    def stale_entries(self) -> List[PathEntry]:
        return [e for e in self.entries if not e.is_valid]

    @property
    def duplicate_entries(self) -> List[PathEntry]:
        return [e for e in self.entries if e.is_duplicate]


@dataclass
class EnvCleanReport:
    cleaned_stale: int = 0
    cleaned_duplicates: int = 0
    user_updated: bool = False
    system_updated: bool = False
    backup_file: Optional[Path] = None
    broadcast_success: bool = False


class EnvironmentCleaner:
    """Manages scanning, deduplication, and cleanup of Windows User & System PATH variables."""

    USER_REG_KEY = (winreg.HKEY_CURRENT_USER, r"Environment")
    SYSTEM_REG_KEY = (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")

    def __init__(self, backup_mgr: RegistryBackupManager, admin_status: bool = False):
        self.backup_mgr = backup_mgr
        self.admin_status = admin_status

    def _read_path_from_registry(self, hkey, subkey: str) -> Tuple[str, int]:
        """Reads the 'Path' value and its registry type from a given registry key."""
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                val, val_type = winreg.QueryValueEx(key, "Path")
                return str(val), val_type
        except FileNotFoundError:
            return "", winreg.REG_EXPAND_SZ
        except Exception:
            return "", winreg.REG_EXPAND_SZ

    def scan(self, progress_callback: Optional[Callable[[str], None]] = None) -> EnvScanReport:
        """Scans User and System PATH variables for stale and duplicate entries."""
        report = EnvScanReport()

        # 1. Scan User PATH
        if progress_callback:
            progress_callback("Scanning User PATH environment variable...")

        user_raw, _ = self._read_path_from_registry(self.USER_REG_KEY[0], self.USER_REG_KEY[1])
        user_entries = self._analyze_raw_path(user_raw, "User")
        report.user_total = len(user_entries)
        report.entries.extend(user_entries)

        # 2. Scan System PATH
        if progress_callback:
            progress_callback("Scanning System PATH environment variable...")

        sys_raw, _ = self._read_path_from_registry(self.SYSTEM_REG_KEY[0], self.SYSTEM_REG_KEY[1])
        sys_entries = self._analyze_raw_path(sys_raw, "System")
        report.system_total = len(sys_entries)
        report.entries.extend(sys_entries)

        report.stale_count = sum(1 for e in report.entries if not e.is_valid)
        report.duplicate_count = sum(1 for e in report.entries if e.is_duplicate)

        return report

    def _analyze_raw_path(self, raw_path: str, scope: str) -> List[PathEntry]:
        """Splits and analyzes individual path segments."""
        if not raw_path:
            return []

        entries: List[PathEntry] = []
        seen_normalized = set()

        raw_parts = [p.strip() for p in raw_path.split(";") if p.strip()]

        for part in raw_parts:
            clean_part = part.strip('"')
            expanded = os.path.expandvars(clean_part)
            norm = os.path.normcase(os.path.normpath(expanded))

            is_duplicate = norm in seen_normalized
            seen_normalized.add(norm)

            try:
                p = Path(expanded)
                is_valid = p.is_dir()
            except Exception:
                is_valid = False

            reason = ""
            if not is_valid:
                reason = "Directory does not exist on disk"
            elif is_duplicate:
                reason = "Duplicate entry in PATH"

            entries.append(
                PathEntry(
                    original=part,
                    expanded=expanded,
                    scope=scope,
                    is_valid=is_valid,
                    is_duplicate=is_duplicate,
                    reason=reason,
                )
            )

        return entries

    def clean(
        self,
        report: EnvScanReport,
        clean_user: bool = True,
        clean_system: bool = True,
        remove_stale: bool = True,
        remove_duplicates: bool = True,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> EnvCleanReport:
        """
        Cleans stale and/or duplicate PATH entries and updates the Windows Registry.
        Enforces single-backup before modifying registry values.
        """
        clean_report = EnvCleanReport()

        user_raw, user_type = self._read_path_from_registry(self.USER_REG_KEY[0], self.USER_REG_KEY[1])
        sys_raw, sys_type = self._read_path_from_registry(self.SYSTEM_REG_KEY[0], self.SYSTEM_REG_KEY[1])

        # Prepare items for backup
        backup_items: List[RegistryBackupItem] = []
        if clean_user and user_raw:
            backup_items.append(
                RegistryBackupItem(
                    root="HKCU",
                    subkey=r"Environment",
                    value_name="Path",
                    value_type=user_type,
                    value_data=user_raw,
                )
            )

        if clean_system and sys_raw and self.admin_status:
            backup_items.append(
                RegistryBackupItem(
                    root="HKLM",
                    subkey=r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                    value_name="Path",
                    value_type=sys_type,
                    value_data=sys_raw,
                )
            )

        if backup_items:
            if progress_callback:
                progress_callback("Backing up current PATH registry values...")
            backup_file = self.backup_mgr.create_backup(backup_items)
            clean_report.backup_file = backup_file

        # Process User PATH
        if clean_user and user_raw:
            if progress_callback:
                progress_callback("Cleaning User PATH...")
            new_user_parts, stale_c, dup_c = self._rebuild_path(
                [e for e in report.entries if e.scope == "User"],
                remove_stale=remove_stale,
                remove_duplicates=remove_duplicates,
            )
            clean_report.cleaned_stale += stale_c
            clean_report.cleaned_duplicates += dup_c

            new_user_str = ";".join(new_user_parts)
            if new_user_str != user_raw:
                self._write_path(self.USER_REG_KEY[0], self.USER_REG_KEY[1], new_user_str, user_type)
                clean_report.user_updated = True

        # Process System PATH (requires admin)
        if clean_system and sys_raw:
            if not self.admin_status:
                if progress_callback:
                    progress_callback("Skipping System PATH (requires Administrator elevation).")
            else:
                if progress_callback:
                    progress_callback("Cleaning System PATH...")
                new_sys_parts, stale_c, dup_c = self._rebuild_path(
                    [e for e in report.entries if e.scope == "System"],
                    remove_stale=remove_stale,
                    remove_duplicates=remove_duplicates,
                )
                clean_report.cleaned_stale += stale_c
                clean_report.cleaned_duplicates += dup_c

                new_sys_str = ";".join(new_sys_parts)
                if new_sys_str != sys_raw:
                    self._write_path(self.SYSTEM_REG_KEY[0], self.SYSTEM_REG_KEY[1], new_sys_str, sys_type)
                    clean_report.system_updated = True

        # Broadcast environment change
        if clean_report.user_updated or clean_report.system_updated:
            if progress_callback:
                progress_callback("Broadcasting environment change to running applications...")
            clean_report.broadcast_success = self._broadcast_environment_change()

        return clean_report

    def _rebuild_path(
        self, entries: List[PathEntry], remove_stale: bool, remove_duplicates: bool
    ) -> Tuple[List[str], int, int]:
        """Reconstructs the PATH list with selected filters applied."""
        rebuilt = []
        seen = set()
        stale_count = 0
        duplicate_count = 0

        for entry in entries:
            norm = os.path.normcase(os.path.normpath(entry.expanded))

            if remove_stale and not entry.is_valid:
                stale_count += 1
                continue

            if remove_duplicates and norm in seen:
                duplicate_count += 1
                continue

            seen.add(norm)
            rebuilt.append(entry.original)

        return rebuilt, stale_count, duplicate_count

    def _write_path(self, hkey, subkey: str, new_path: str, val_type: int) -> None:
        """Writes the updated PATH value to registry."""
        with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "Path", 0, val_type, new_path)

    @staticmethod
    def _broadcast_environment_change() -> bool:
        """
        Broadcasts WM_SETTINGCHANGE with lParam="Environment" so open shells and
        applications refresh their environment without needing a Windows restart.
        """
        try:
            HWND_BROADCAST = 0xFFFF
            WM_SETTINGCHANGE = 0x001A
            SMTO_ABORTIFHUNG = 0x0002
            result = ctypes.c_ulong()
            ret = ctypes.windll.user32.SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                "Environment",
                SMTO_ABORTIFHUNG,
                5000,
                ctypes.byref(result),
            )
            return ret != 0
        except Exception:
            return False
