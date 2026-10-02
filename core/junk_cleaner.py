"""
Deep Junk & Privacy Cleaner Engine for SysCare
Safely cleans temporary files, recent documents, search/run history, browser caches,
developer caches, crash dumps, and uninstalled app leftovers without touching user data.
"""

import ctypes
import os
import shutil
import subprocess
import sys
import winreg
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

from core.config import ConfigManager


@dataclass
class CleanupItem:
    category: str
    path: str
    size_bytes: int = 0
    is_registry: bool = False
    description: str = ""


@dataclass
class CleanupReport:
    categories: Dict[str, Dict[str, int]] = field(default_factory=dict)
    total_files: int = 0
    total_bytes: int = 0
    cleaned_files: int = 0
    reclaimed_bytes: int = 0
    details: List[str] = field(default_factory=list)

    def add_category_stat(self, category: str, found_items: int, found_bytes: int,
                          cleaned_items: int = 0, reclaimed_bytes: int = 0) -> None:
        if category not in self.categories:
            self.categories[category] = {
                "found_items": 0,
                "found_bytes": 0,
                "cleaned_items": 0,
                "reclaimed_bytes": 0,
            }
        self.categories[category]["found_items"] += found_items
        self.categories[category]["found_bytes"] += found_bytes
        self.categories[category]["cleaned_items"] += cleaned_items
        self.categories[category]["reclaimed_bytes"] += reclaimed_bytes

        self.total_files += found_items
        self.total_bytes += found_bytes
        self.cleaned_files += cleaned_items
        self.reclaimed_bytes += reclaimed_bytes


class JunkCleaner:
    # Essential Windows and system directories that MUST NEVER be deleted
    PROTECTED_DIR_NAMES = {
        "microsoft", "windows", "system32", "syswow64", "packages", "programs",
        "temp", "virtualstore", "appdata", "assembly", "common files", "internet explorer",
        "windows nt", "windows defender", "windows mail", "windows media player",
        "windows powershell", "system volume information", "$recycle.bin", "syscare"
    }

    def __init__(self, config_mgr: ConfigManager, is_admin: bool = False):
        self.config = config_mgr
        self.is_admin = is_admin

    def _is_excluded(self, path_str: str) -> bool:
        return self.config.is_excluded_directory(path_str)

    def clean_all(self, dry_run: bool = False, progress_callback: Optional[Callable[[str], None]] = None) -> CleanupReport:
        """Executes full scan or cleanup based on active configuration toggles."""
        report = CleanupReport()

        steps = [
            ("User Temporary Files", self._clean_user_temp),
            ("Windows System Temp", self._clean_system_temp),
            ("Crash Dumps & Error Reports", self._clean_crash_dumps),
            ("Recent Docs & JumpLists", self._clean_recent_docs),
            ("Explorer Search & RunMRU History", self._clean_explorer_history),
            ("Browser Caches (Safe Mode)", self._clean_browser_caches),
            ("Developer & Package Caches", self._clean_dev_caches),
            ("Uninstalled App Leftovers", self._clean_app_leftovers),
            ("Recycle Bin", self._clean_recycle_bin),
            ("DNS Resolver Cache", self._flush_dns_cache),
        ]

        for name, func in steps:
            if progress_callback:
                progress_callback(f"Processing {name}...")
            try:
                func(dry_run, report)
            except Exception as e:
                report.details.append(f"Error in {name}: {e}")

        return report

    @classmethod
    def _is_critical_path(cls, path: Path) -> bool:
        """Strict safety guard to guarantee sensitive system or user personal directories are NEVER touched."""
        try:
            resolved = path.resolve()
        except Exception:
            resolved = path

        # 1. Drive roots: C:\, D:\, etc.
        if len(resolved.parts) <= 1 or resolved.parent == resolved:
            return True

        # 2. User root: C:\Users\Username
        user_profile = os.environ.get("USERPROFILE")
        if user_profile and resolved == Path(user_profile).resolve():
            return True

        # 3. System roots: C:\Windows, C:\Windows\System32, Program Files
        windir = os.environ.get("WINDIR", "C:\\Windows")
        if resolved in (Path(windir).resolve(), (Path(windir) / "System32").resolve()):
            return True
        for pf in (r"C:\Program Files", r"C:\Program Files (x86)"):
            if resolved == Path(pf).resolve():
                return True

        # 4. User personal folders: Desktop, Documents, Downloads, Pictures, Music, Videos
        if user_profile:
            u_path = Path(user_profile)
            for personal in ("Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos", "Saved Games"):
                if resolved == (u_path / personal).resolve():
                    return True

        return False

    def _delete_file_safely(self, file_path: Path) -> int:
        """Attempts to delete a file safely. Returns file size if deleted, 0 if skipped or locked."""
        try:
            if not file_path.is_file() and not file_path.is_symlink():
                return 0
            size = file_path.stat().st_size
            file_path.unlink(missing_ok=True)
            return size
        except (PermissionError, OSError):
            return 0

    def _clean_directory_contents(self, dir_path: Path, dry_run: bool, category: str, report: CleanupReport) -> None:
        """Cleans files and subdirectories inside dir_path without removing dir_path itself."""
        if not dir_path.exists() or not dir_path.is_dir():
            return
        if self._is_critical_path(dir_path):
            return
        if self._is_excluded(str(dir_path)):
            return

        found_count = 0
        found_bytes = 0
        cleaned_count = 0
        reclaimed_bytes = 0

        # Scan files safely; never follow symlinks outside target
        for root, dirs, files in os.walk(str(dir_path), topdown=False, followlinks=False):
            # Check for symlinked / junction directory roots
            if os.path.islink(root) or self._is_critical_path(Path(root)):
                continue
            if self._is_excluded(root):
                continue
            for f in files:
                fp = Path(root) / f
                try:
                    sz = fp.stat().st_size
                    found_count += 1
                    found_bytes += sz
                    if not dry_run:
                        reclaimed = self._delete_file_safely(fp)
                        if reclaimed > 0 or not fp.exists():
                            cleaned_count += 1
                            reclaimed_bytes += sz
                except (PermissionError, OSError):
                    pass

            # Try to remove empty subdirectories (skips symlinks)
            if not dry_run:
                for d in dirs:
                    dp = Path(root) / d
                    if not os.path.islink(str(dp)):
                        try:
                            dp.rmdir()
                        except (PermissionError, OSError):
                            pass

        report.add_category_stat(category, found_count, found_bytes, cleaned_count, reclaimed_bytes)

    # 1. User Temp Files (%TEMP%)
    def _clean_user_temp(self, dry_run: bool, report: CleanupReport) -> None:
        if not self.config.get("clean_user_temp", True):
            return
        temp_env = os.environ.get("TEMP")
        if temp_env:
            self._clean_directory_contents(Path(temp_env), dry_run, "User Temp Files", report)

    # 2. Windows System Temp (C:\Windows\Temp)
    def _clean_system_temp(self, dry_run: bool, report: CleanupReport) -> None:
        if not self.config.get("clean_system_temp", True):
            return
        windir = os.environ.get("WINDIR", "C:\\Windows")
        sys_temp = Path(windir) / "Temp"
        if sys_temp.exists():
            self._clean_directory_contents(sys_temp, dry_run, "Windows System Temp", report)

        # SoftwareDistribution download cache (only if admin)
        if self.is_admin:
            sd_download = Path(windir) / "SoftwareDistribution" / "Download"
            if sd_download.exists():
                self._clean_directory_contents(sd_download, dry_run, "Windows Update Downloads", report)

    # 3. Crash Dumps & Windows Error Reporting
    def _clean_crash_dumps(self, dry_run: bool, report: CleanupReport) -> None:
        if not self.config.get("clean_crash_dumps", True):
            return

        local_app_data = os.environ.get("LOCALAPPDATA")
        prog_data = os.environ.get("PROGRAMDATA", "C:\\ProgramData")

        target_dirs = []
        if local_app_data:
            target_dirs.append(Path(local_app_data) / "CrashDumps")
            target_dirs.append(Path(local_app_data) / "Microsoft" / "Windows" / "WER")

        if prog_data:
            target_dirs.append(Path(prog_data) / "Microsoft" / "Windows" / "WER" / "ReportArchive")
            target_dirs.append(Path(prog_data) / "Microsoft" / "Windows" / "WER" / "ReportQueue")
            target_dirs.append(Path(prog_data) / "Microsoft" / "Windows" / "WER" / "Temp")

        for d in target_dirs:
            if d.exists():
                self._clean_directory_contents(d, dry_run, "Crash Dumps & Error Reports", report)

    # 4. Recent Documents & JumpLists (Preserves user-pinned CustomDestinations!)
    def _clean_recent_docs(self, dry_run: bool, report: CleanupReport) -> None:
        if not self.config.get("clean_recent_docs", True):
            return

        app_data = os.environ.get("APPDATA")
        if not app_data:
            return

        recent_dir = Path(app_data) / "Microsoft" / "Windows" / "Recent"
        if not recent_dir.exists():
            return

        # 1. Clean loose shortcut files in Recent
        found_count = 0
        found_bytes = 0
        cleaned_count = 0
        reclaimed_bytes = 0

        for item in recent_dir.glob("*.lnk"):
            try:
                sz = item.stat().st_size
                found_count += 1
                found_bytes += sz
                if not dry_run:
                    sz_del = self._delete_file_safely(item)
                    if sz_del > 0 or not item.exists():
                        cleaned_count += 1
                        reclaimed_bytes += sz
            except (PermissionError, OSError):
                pass

        report.add_category_stat("Recent Docs & JumpLists", found_count, found_bytes, cleaned_count, reclaimed_bytes)

        # 2. Clean AutomaticDestinations (automatic JumpLists), but NEVER touch CustomDestinations (pinned favorites)
        auto_dest = recent_dir / "AutomaticDestinations"
        if auto_dest.exists():
            self._clean_directory_contents(auto_dest, dry_run, "Recent Docs & JumpLists", report)

    # 5. Explorer Search & RunMRU History (Registry & Cache)
    def _clean_explorer_history(self, dry_run: bool, report: CleanupReport) -> None:
        if not self.config.get("clean_explorer_history", True):
            return

        mru_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"),
        ]

        found_entries = 0
        cleaned_entries = 0

        for hkey, subkey_path in mru_keys:
            try:
                with winreg.OpenKey(hkey, subkey_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                    count_subkeys, count_values, _ = winreg.QueryInfoKey(key)
                    found_entries += count_values
                    if not dry_run:
                        # Collect value names first
                        val_names = [winreg.EnumValue(key, i)[0] for i in range(count_values)]
                        for vn in val_names:
                            try:
                                winreg.DeleteValue(key, vn)
                                cleaned_entries += 1
                            except Exception:
                                pass
            except FileNotFoundError:
                pass
            except Exception:
                pass

        report.add_category_stat("Explorer Search & Run History", found_entries, 0, cleaned_entries, 0)

    # 6. Browser Caches (Safe Mode - never cookies or passwords)
    def _clean_browser_caches(self, dry_run: bool, report: CleanupReport) -> None:
        if not self.config.get("clean_browser_caches", True):
            return

        local_app_data = os.environ.get("LOCALAPPDATA")
        app_data = os.environ.get("APPDATA")
        if not local_app_data:
            return

        cache_dirs: List[Path] = []

        # Google Chrome
        chrome_base = Path(local_app_data) / "Google" / "Chrome" / "User Data"
        if chrome_base.exists():
            for profile in chrome_base.glob("*"):
                if profile.is_dir():
                    cache_dirs.append(profile / "Cache")
                    cache_dirs.append(profile / "Code Cache")
                    cache_dirs.append(profile / "GPUCache")

        # Microsoft Edge
        edge_base = Path(local_app_data) / "Microsoft" / "Edge" / "User Data"
        if edge_base.exists():
            for profile in edge_base.glob("*"):
                if profile.is_dir():
                    cache_dirs.append(profile / "Cache")
                    cache_dirs.append(profile / "Code Cache")
                    cache_dirs.append(profile / "GPUCache")

        # Brave Browser
        brave_base = Path(local_app_data) / "BraveSoftware" / "Brave-Browser" / "User Data"
        if brave_base.exists():
            for profile in brave_base.glob("*"):
                if profile.is_dir():
                    cache_dirs.append(profile / "Cache")
                    cache_dirs.append(profile / "Code Cache")
                    cache_dirs.append(profile / "GPUCache")

        # Mozilla Firefox
        if local_app_data:
            ff_cache = Path(local_app_data) / "Mozilla" / "Firefox" / "Profiles"
            if ff_cache.exists():
                for prof in ff_cache.glob("*"):
                    cache_dirs.append(prof / "cache2")

        for c_dir in cache_dirs:
            if c_dir.exists():
                self._clean_directory_contents(c_dir, dry_run, "Browser Caches (Safe)", report)

    # 7. Developer & Package Caches
    def _clean_dev_caches(self, dry_run: bool, report: CleanupReport) -> None:
        if not self.config.get("clean_dev_caches", True):
            return

        user_profile = os.environ.get("USERPROFILE")
        local_app_data = os.environ.get("LOCALAPPDATA")
        app_data = os.environ.get("APPDATA")

        dev_dirs = []
        if local_app_data:
            dev_dirs.append(Path(local_app_data) / "pip" / "cache")
            dev_dirs.append(Path(local_app_data) / "NuGet" / "v3-cache")
        if app_data:
            dev_dirs.append(Path(app_data) / "npm-cache")

        for d in dev_dirs:
            if d.exists():
                self._clean_directory_contents(d, dry_run, "Developer & Package Caches", report)

    # 8. Uninstalled App Leftovers
    def _get_installed_app_names(self) -> Set[str]:
        """Gathers tokens of installed apps from registry and program files."""
        names = set()
        roots = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        for hkey, subkey in roots:
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                    num_subkeys, _, _ = winreg.QueryInfoKey(key)
                    for i in range(num_subkeys):
                        try:
                            sub_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, sub_name) as app_key:
                                try:
                                    display_name, _ = winreg.QueryValueEx(app_key, "DisplayName")
                                    if display_name:
                                        names.add(display_name.lower().strip())
                                        for part in display_name.lower().split():
                                            if len(part) > 3:
                                                names.add(part)
                                except Exception:
                                    pass
                        except Exception:
                            pass
            except Exception:
                pass

        # Also add folder names from Program Files
        for pfiles in [r"C:\Program Files", r"C:\Program Files (x86)"]:
            p = Path(pfiles)
            if p.exists():
                for child in p.iterdir():
                    if child.is_dir():
                        names.add(child.name.lower())

        return names

    def _clean_app_leftovers(self, dry_run: bool, report: CleanupReport) -> None:
        """
        Scans %LOCALAPPDATA% and %APPDATA% for empty leftover folders
        left behind by uninstalled applications.
        """
        if not self.config.get("clean_app_leftovers", True):
            return

        locations = []
        if os.environ.get("LOCALAPPDATA"):
            locations.append(Path(os.environ["LOCALAPPDATA"]))
        if os.environ.get("APPDATA"):
            locations.append(Path(os.environ["APPDATA"]))

        found_leftovers = 0
        cleaned_leftovers = 0

        for base_dir in locations:
            if not base_dir.exists():
                continue
            try:
                for item in base_dir.iterdir():
                    if not item.is_dir() or item.name.lower() in self.PROTECTED_DIR_NAMES:
                        continue
                    if self._is_excluded(str(item)):
                        continue

                    # Check if empty folder (common uninstallation leftover)
                    try:
                        # Test if directory is empty
                        has_entries = any(item.iterdir())
                        if not has_entries:
                            found_leftovers += 1
                            if not dry_run:
                                item.rmdir()
                                cleaned_leftovers += 1
                    except (PermissionError, OSError):
                        pass
            except Exception:
                pass

        report.add_category_stat("Uninstalled App Leftovers", found_leftovers, 0, cleaned_leftovers, 0)

    # 9. Empty Recycle Bin
    def _clean_recycle_bin(self, dry_run: bool, report: CleanupReport) -> None:
        if not self.config.get("clean_recycle_bin", True):
            return
        if dry_run:
            # Indicate recycle bin will be emptied
            report.add_category_stat("Recycle Bin", 1, 0, 0, 0)
            return

        try:
            # SHERB_NOCONFIRMATION = 0x00000001
            # SHERB_NOPROGRESSUI   = 0x00000002
            # SHERB_NOSOUND        = 0x00000004
            flags = 0x00000001 | 0x00000002 | 0x00000004
            res = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, flags)
            # S_OK is 0, or E_UNEXPECTED / empty bin
            report.add_category_stat("Recycle Bin", 1, 0, 1, 0)
        except Exception as e:
            report.details.append(f"Recycle bin error: {e}")

    # 10. DNS Flush
    def _flush_dns_cache(self, dry_run: bool, report: CleanupReport) -> None:
        if not self.config.get("flush_dns", True):
            return
        if dry_run:
            report.add_category_stat("DNS Resolver Cache", 1, 0, 0, 0)
            return

        try:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, check=False)
            report.add_category_stat("DNS Resolver Cache", 1, 0, 1, 0)
        except Exception:
            pass
