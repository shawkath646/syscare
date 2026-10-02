"""
Registry Cleaner Engine for SysCare
Safely scans for orphaned uninstall entries, broken startup items, dead app paths,
stale file associations, and outdated MUI cache entries.
Enforces strict single-backup rule: automatically deletes any previous backup before creating new one.
"""

import os
import re
import winreg
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from core.config import ConfigManager
from core.safety import RegistryBackupItem, RegistryBackupManager


@dataclass
class RegistryIssue:
    category: str
    root: str                    # "HKCU" or "HKLM"
    subkey: str
    value_name: Optional[str]    # None if the whole key is targeted
    value_data: Optional[str]
    value_type: Optional[int]
    reason: str


@dataclass
class RegistryReport:
    issues: List[RegistryIssue] = field(default_factory=list)
    cleaned_count: int = 0
    categories_count: Dict[str, int] = field(default_factory=dict)
    backup_file: Optional[Path] = None
    errors: List[str] = field(default_factory=list)

    def add_issue(self, issue: RegistryIssue) -> None:
        self.issues.append(issue)
        cat = issue.category
        self.categories_count[cat] = self.categories_count.get(cat, 0) + 1


class RegistryCleaner:
    def __init__(self, config_mgr: ConfigManager, backup_mgr: RegistryBackupManager, is_admin: bool = False):
        self.config = config_mgr
        self.backup_mgr = backup_mgr
        self.is_admin = is_admin

    def _is_excluded(self, key_path: str) -> bool:
        return self.config.is_excluded_registry(key_path)

    @staticmethod
    def _extract_executable_path(command_str: str) -> str:
        """
        Safely and accurately extracts the target binary path from a command line string.
        Handles quoted paths, unquoted paths with spaces, command flags, and comma indices.
        """
        if not command_str:
            return ""
        s = command_str.strip()

        # 1. Match quoted string first: "C:\Path with spaces\app.exe" ...
        if s.startswith('"'):
            end_quote = s.find('"', 1)
            if end_quote != -1:
                raw = s[1:end_quote].strip()
                return re.sub(r',\s*-?\d+$', '', raw)
            s = s.strip('"')

        # 2. Check if whole unquoted string exists on disk directly
        expanded = os.path.expandvars(s)
        if os.path.exists(expanded):
            return expanded

        # 3. Strip comma parameters (e.g. shell32.dll,Control_RunDLL or app.exe,0)
        comma_part = s.split(',')[0].strip()
        if os.path.exists(os.path.expandvars(comma_part)):
            return comma_part

        # 4. Search for common Windows executable extensions (.exe, .dll, .cpl, .bat, .cmd)
        ext_pattern = re.compile(r'^(.*?\.(?:exe|dll|cpl|bat|cmd|ocx))(?:\s+.*|,.*)?$', re.IGNORECASE)
        m = ext_pattern.match(s)
        if m:
            candidate = m.group(1).strip().strip('"')
            if os.path.exists(os.path.expandvars(candidate)):
                return candidate

        # 5. Progressive space accumulation (handles unquoted paths with spaces)
        parts = s.split()
        accum = ""
        for p in parts:
            accum = f"{accum} {p}".strip()
            exp_accum = os.path.expandvars(accum)
            if os.path.exists(exp_accum):
                return exp_accum
            if os.path.exists(f"{exp_accum}.exe"):
                return f"{exp_accum}.exe"

        # Fallback: first token stripped of commas/quotes
        first_token = parts[0].strip('",') if parts else s
        return re.sub(r',\s*-?\d+$', '', first_token)

    @staticmethod
    def _target_exists(file_path: str) -> bool:
        """Checks if a target file or directory exists, expanding environment variables."""
        if not file_path:
            return True  # If cannot determine, consider it safe to avoid false positives

        clean_path = re.sub(r',\s*-?\d+$', '', file_path.strip('", \t'))
        if not clean_path:
            return True

        # Common Windows built-ins that always exist
        base_name = os.path.basename(clean_path).lower()
        if base_name in ("rundll32.exe", "regsvr32.exe", "cmd.exe", "powershell.exe", "msiexec.exe", "explorer.exe"):
            return True

        expanded = os.path.expandvars(clean_path).strip()
        try:
            p = Path(expanded)
            if p.exists():
                return True
            # Check with .exe if omitted
            if not p.suffix and p.with_suffix(".exe").exists():
                return True
            # Check in System32 / Windows path
            sys32 = Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32" / expanded
            if sys32.exists():
                return True
        except Exception:
            return True
        return False

    def scan(self, progress_callback: Optional[Callable[[str], None]] = None) -> RegistryReport:
        """Scans the registry for broken / orphaned entries without modifying anything."""
        report = RegistryReport()

        scanners = [
            ("Broken Startup Items", self._scan_startup_items),
            ("Orphaned Uninstall Entries", self._scan_uninstall_leftovers),
            ("Missing App Paths", self._scan_app_paths),
            ("Stale MUI Cache Entries", self._scan_mui_cache),
            ("Stale OpenWith Associations", self._scan_openwith_entries),
        ]

        for name, scan_func in scanners:
            if progress_callback:
                progress_callback(f"Scanning {name}...")
            try:
                scan_func(report)
            except Exception as e:
                report.errors.append(f"Error scanning {name}: {e}")

        return report

    def clean(self, report: RegistryReport, progress_callback: Optional[Callable[[str], None]] = None) -> RegistryReport:
        """
        Takes scanned issues, creates a single .reg backup (overwriting any previous backup),
        and applies the cleanups safely.
        """
        if not report.issues:
            return report

        if progress_callback:
            progress_callback("Enforcing single backup policy & preparing backup...")

        # 1. Prepare items for backup
        backup_items: List[RegistryBackupItem] = []
        for issue in report.issues:
            backup_items.append(RegistryBackupItem(
                root=issue.root,
                subkey=issue.subkey,
                value_name=issue.value_name,
                value_type=issue.value_type,
                value_data=issue.value_data
            ))

        # 2. Automatically delete previous backup and create the fresh one
        backup_file = self.backup_mgr.create_backup(backup_items)
        report.backup_file = backup_file

        if progress_callback:
            progress_callback("Applying registry cleanups...")

        import subprocess
        cleaned_count = 0
        for issue in report.issues:
            root_hkey = winreg.HKEY_LOCAL_MACHINE if issue.root == "HKLM" else winreg.HKEY_CURRENT_USER
            full_root_str = "HKEY_LOCAL_MACHINE" if issue.root == "HKLM" else "HKEY_CURRENT_USER"
            try:
                if issue.value_name is not None:
                    # Specific value deletion
                    with winreg.OpenKey(root_hkey, issue.subkey, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.DeleteValue(key, issue.value_name)
                        cleaned_count += 1
                else:
                    # Entire key deletion (e.g. orphaned app path or uninstalled key)
                    full_key_target = f"{full_root_str}\\{issue.subkey}"
                    del_res = subprocess.run(
                        ["reg.exe", "delete", full_key_target, "/f"],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    if del_res.returncode == 0:
                        cleaned_count += 1
                    else:
                        # Fallback to winreg
                        try:
                            winreg.DeleteKey(root_hkey, issue.subkey)
                            cleaned_count += 1
                        except Exception as e:
                            report.errors.append(f"Could not delete key {full_key_target}: {e}")
            except Exception as e:
                report.errors.append(f"Could not delete {issue.root}\\{issue.subkey} ({issue.value_name}): {e}")

        report.cleaned_count = cleaned_count
        return report

    # 1. Startup Items (Run / RunOnce)
    def _scan_startup_items(self, report: RegistryReport) -> None:
        if not self.config.get("registry_clean_broken_startup", True):
            return

        locations = [
            ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        if self.is_admin:
            locations.extend([
                ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            ])

        for root_str, hkey, subkey in locations:
            if self._is_excluded(f"{root_str}\\{subkey}"):
                continue
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                    num_subkeys, num_values, _ = winreg.QueryInfoKey(key)
                    for i in range(num_values):
                        try:
                            val_name, val_data, val_type = winreg.EnumValue(key, i)
                            exe = self._extract_executable_path(str(val_data))
                            if exe and not self._target_exists(exe):
                                report.add_issue(RegistryIssue(
                                    category="Broken Startup Items",
                                    root=root_str,
                                    subkey=subkey,
                                    value_name=val_name,
                                    value_data=val_data,
                                    value_type=val_type,
                                    reason=f"Startup executable missing: {exe}"
                                ))
                        except Exception:
                            pass
            except FileNotFoundError:
                pass
            except Exception:
                pass

    # 2. Orphaned Uninstall Leftovers
    def _scan_uninstall_leftovers(self, report: RegistryReport) -> None:
        if not self.config.get("registry_clean_uninstall_leftovers", True):
            return

        locations = [
            ("HKCU", winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        if self.is_admin:
            locations.extend([
                ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            ])

        for root_str, hkey, base_subkey in locations:
            if self._is_excluded(f"{root_str}\\{base_subkey}"):
                continue
            try:
                with winreg.OpenKey(hkey, base_subkey, 0, winreg.KEY_READ) as key:
                    num_subkeys, _, _ = winreg.QueryInfoKey(key)
                    for i in range(num_subkeys):
                        try:
                            sub_name = winreg.EnumKey(key, i)
                            full_sub = f"{base_subkey}\\{sub_name}"
                            with winreg.OpenKey(hkey, full_sub, 0, winreg.KEY_READ) as app_key:
                                # Check SystemComponent flag (never touch system components)
                                try:
                                    sys_comp, _ = winreg.QueryValueEx(app_key, "SystemComponent")
                                    if sys_comp == 1:
                                        continue
                                except Exception:
                                    pass

                                uninstall_str = None
                                try:
                                    uninstall_str, _ = winreg.QueryValueEx(app_key, "UninstallString")
                                except Exception:
                                    pass

                                install_loc = None
                                try:
                                    install_loc, _ = winreg.QueryValueEx(app_key, "InstallLocation")
                                except Exception:
                                    pass

                                display_name = sub_name
                                try:
                                    dn, _ = winreg.QueryValueEx(app_key, "DisplayName")
                                    if dn:
                                        display_name = dn
                                except Exception:
                                    pass

                                # If both uninstall string and install location point to missing paths
                                if uninstall_str:
                                    uninst_exe = self._extract_executable_path(str(uninstall_str))
                                    # If uninstall string is MsiExec.exe, it's an MSI installer, don't flag unless install_loc is missing
                                    if "msiexec" in uninst_exe.lower():
                                        continue

                                    exe_missing = uninst_exe and not self._target_exists(uninst_exe)
                                    loc_missing = install_loc and not self._target_exists(str(install_loc))

                                    if exe_missing and (install_loc is None or loc_missing):
                                        report.add_issue(RegistryIssue(
                                            category="Orphaned Uninstall Entries",
                                            root=root_str,
                                            subkey=full_sub,
                                            value_name=None,  # Key itself
                                            value_data=full_sub,
                                            value_type=None,
                                            reason=f"Uninstalled leftover for '{display_name}' (missing: {uninst_exe})"
                                        ))
                        except Exception:
                            pass
            except FileNotFoundError:
                pass
            except Exception:
                pass

    # 3. Missing App Paths
    def _scan_app_paths(self, report: RegistryReport) -> None:
        if not self.config.get("registry_clean_missing_app_paths", True):
            return

        locations = [
            ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\App Paths"),
        ]
        if self.is_admin:
            locations.append(("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"))

        for root_str, hkey, base_subkey in locations:
            if self._is_excluded(f"{root_str}\\{base_subkey}"):
                continue
            try:
                with winreg.OpenKey(hkey, base_subkey, 0, winreg.KEY_READ) as key:
                    num_subkeys, _, _ = winreg.QueryInfoKey(key)
                    for i in range(num_subkeys):
                        try:
                            app_sub = winreg.EnumKey(key, i)
                            full_sub = f"{base_subkey}\\{app_sub}"
                            with winreg.OpenKey(hkey, full_sub, 0, winreg.KEY_READ) as path_key:
                                try:
                                    def_val, vtype = winreg.QueryValueEx(path_key, "")
                                    exe = self._extract_executable_path(str(def_val))
                                    if exe and not self._target_exists(exe):
                                        report.add_issue(RegistryIssue(
                                            category="Missing App Paths",
                                            root=root_str,
                                            subkey=full_sub,
                                            value_name=None,
                                            value_data=full_sub,
                                            value_type=None,
                                            reason=f"App Path points to missing file: {exe}"
                                        ))
                                except FileNotFoundError:
                                    pass
                        except Exception:
                            pass
            except FileNotFoundError:
                pass
            except Exception:
                pass

    # 4. Stale Shell MUI Cache
    def _scan_mui_cache(self, report: RegistryReport) -> None:
        if not self.config.get("registry_clean_mui_cache", True):
            return

        subkey = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
        root_str = "HKCU"
        if self._is_excluded(f"{root_str}\\{subkey}"):
            return

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_READ) as key:
                _, num_values, _ = winreg.QueryInfoKey(key)
                for i in range(num_values):
                    try:
                        val_name, val_data, val_type = winreg.EnumValue(key, i)
                        # Value names in MuiCache are often "C:\Path\To\app.exe.FriendlyAppName" or "C:\Path\To\app.exe"
                        clean_path = val_name
                        for suffix in [".FriendlyAppName", ".ApplicationCompany"]:
                            if clean_path.endswith(suffix):
                                clean_path = clean_path[:-len(suffix)]
                                break

                        # Check if it looks like a path
                        if (":" in clean_path or clean_path.startswith("\\")) and clean_path.lower().endswith(".exe"):
                            if not self._target_exists(clean_path):
                                report.add_issue(RegistryIssue(
                                    category="Stale MUI Cache Entries",
                                    root=root_str,
                                    subkey=subkey,
                                    value_name=val_name,
                                    value_data=val_data,
                                    value_type=val_type,
                                    reason=f"Target executable deleted: {clean_path}"
                                ))
                    except Exception:
                        pass
        except FileNotFoundError:
            pass
        except Exception:
            pass

    # 5. Stale OpenWith Entries
    def _scan_openwith_entries(self, report: RegistryReport) -> None:
        if not self.config.get("registry_clean_stale_openwith", True):
            return

        base_subkey = r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
        root_str = "HKCU"
        if self._is_excluded(f"{root_str}\\{base_subkey}"):
            return

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_subkey, 0, winreg.KEY_READ) as base_key:
                num_subkeys, _, _ = winreg.QueryInfoKey(base_key)
                for i in range(num_subkeys):
                    try:
                        ext = winreg.EnumKey(base_key, i)
                        openwith_sub = f"{base_subkey}\\{ext}\\OpenWithList"
                        try:
                            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, openwith_sub, 0, winreg.KEY_READ) as ow_key:
                                _, num_vals, _ = winreg.QueryInfoKey(ow_key)
                                for v in range(num_vals):
                                    try:
                                        vn, vd, vt = winreg.EnumValue(ow_key, v)
                                        if vn == "MRUList":
                                            continue
                                        exe = str(vd).strip()
                                        if exe.lower().endswith(".exe") and not self._target_exists(exe):
                                            report.add_issue(RegistryIssue(
                                                category="Stale OpenWith Associations",
                                                root=root_str,
                                                subkey=openwith_sub,
                                                value_name=vn,
                                                value_data=vd,
                                                value_type=vt,
                                                reason=f"Associated executable missing for {ext}: {exe}"
                                            ))
                                    except Exception:
                                        pass
                        except FileNotFoundError:
                            pass
                    except Exception:
                        pass
        except FileNotFoundError:
            pass
        except Exception:
            pass
