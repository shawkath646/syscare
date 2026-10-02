"""
Multi-Version Installed Application Detector & Cleaner for SysCare
Identifies applications with multiple versions installed concurrently (e.g. Python 2/3, old CUDA, old Java/Node),
and allows cleanly uninstalling or purging outdated versions.
"""

import glob
import os
import re
import shutil
import subprocess
import winreg
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


@dataclass
class InstalledAppInfo:
    display_name: str
    version: str
    version_tuple: Tuple[int, ...]
    install_location: str
    uninstall_string: str
    quiet_uninstall_string: str
    registry_root: str
    registry_key: str
    is_disk_only: bool = False


@dataclass
class DuplicateAppGroup:
    base_name: str
    latest_app: InstalledAppInfo
    older_apps: List[InstalledAppInfo] = field(default_factory=list)


class MultiVersionDetector:
    # Applications known to commonly have multiple co-existing versions
    KNOWN_MULTI_TARGETS = [
        "python", "node.js", "java", "openjdk", "cuda", "visual studio",
        "go programming", "git", "dotnet", "sdk", "7-zip", "winrar", "notepad++"
    ]

    @staticmethod
    def _parse_version(v_str: str) -> Tuple[int, ...]:
        """Extracts integers from a version string to enable accurate semantic comparison."""
        if not v_str:
            return (0,)
        parts = re.findall(r'\d+', v_str)
        if parts:
            return tuple(int(p) for p in parts[:6])
        return (0,)

    @staticmethod
    def _normalize_app_name(name: str) -> str:
        """Strips version numbers, build architectures, and tags to find base product name."""
        if not name:
            return ""
        s = name.strip()
        # Remove architecture tags
        s = re.sub(r'\b(\(64-bit\)|\(32-bit\)|64-bit|32-bit|amd64|x64|x86|win64|win32)\b', '', s, flags=re.IGNORECASE)
        # Remove version strings like "3.14.6", "v18.2.0", "13.2"
        s = re.sub(r'\b(v?\d+(\.\d+)+[a-z0-9_.-]*)\b', '', s, flags=re.IGNORECASE)
        # Remove trailing release tags or isolated numbers (e.g., "Python 3" -> "Python")
        s = re.sub(r'\b(Python\s+\d+)\b', 'Python', s, flags=re.IGNORECASE)
        s = re.sub(r'\s+', ' ', s).strip(' -_,()[]')
        return s

    def get_installed_apps_from_registry(self) -> List[InstalledAppInfo]:
        """Scans Windows Registry for all registered installed software."""
        roots = [
            ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            ("HKCU", winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]

        apps: List[InstalledAppInfo] = []

        for root_str, hkey, base_subkey in roots:
            try:
                with winreg.OpenKey(hkey, base_subkey, 0, winreg.KEY_READ) as key:
                    num_subkeys, _, _ = winreg.QueryInfoKey(key)
                    for i in range(num_subkeys):
                        try:
                            sub_name = winreg.EnumKey(key, i)
                            full_sub = f"{base_subkey}\\{sub_name}"
                            with winreg.OpenKey(hkey, full_sub, 0, winreg.KEY_READ) as app_key:
                                try:
                                    dn, _ = winreg.QueryValueEx(app_key, "DisplayName")
                                    if not dn or not str(dn).strip():
                                        continue
                                    display_name = str(dn).strip()
                                except Exception:
                                    continue

                                # Ignore Windows updates and system components
                                try:
                                    sys_comp, _ = winreg.QueryValueEx(app_key, "SystemComponent")
                                    if sys_comp == 1:
                                        continue
                                except Exception:
                                    pass

                                ver = ""
                                try:
                                    v, _ = winreg.QueryValueEx(app_key, "DisplayVersion")
                                    ver = str(v).strip()
                                except Exception:
                                    pass

                                uninst = ""
                                try:
                                    u, _ = winreg.QueryValueEx(app_key, "UninstallString")
                                    uninst = str(u).strip()
                                except Exception:
                                    pass

                                quiet_uninst = ""
                                try:
                                    qu, _ = winreg.QueryValueEx(app_key, "QuietUninstallString")
                                    quiet_uninst = str(qu).strip()
                                except Exception:
                                    pass

                                loc = ""
                                try:
                                    l_val, _ = winreg.QueryValueEx(app_key, "InstallLocation")
                                    loc = str(l_val).strip()
                                except Exception:
                                    pass

                                apps.append(InstalledAppInfo(
                                    display_name=display_name,
                                    version=ver,
                                    version_tuple=self._parse_version(ver or display_name),
                                    install_location=loc,
                                    uninstall_string=uninst,
                                    quiet_uninstall_string=quiet_uninst,
                                    registry_root=root_str,
                                    registry_key=full_sub
                                ))
                        except Exception:
                            pass
            except Exception:
                pass

        return apps

    def scan_disk_pythons(self) -> List[InstalledAppInfo]:
        """Scans disk directories for Python installations (C:\\Python* and AppData)."""
        found: List[InstalledAppInfo] = []
        candidates = glob.glob(r"C:\Python*")
        local_app = os.environ.get("LOCALAPPDATA")
        if local_app:
            candidates.extend(glob.glob(f"{local_app}\\Programs\\Python\\Python*"))

        for c in candidates:
            p = Path(c)
            py_exe = p / "python.exe"
            if py_exe.exists():
                ver_str = ""
                # Try to get python version from directory name or binary
                m = re.search(r'Python(\d)(\d+)?', p.name, re.IGNORECASE)
                if m:
                    major = m.group(1)
                    minor = m.group(2) or "0"
                    ver_str = f"{major}.{minor}"
                found.append(InstalledAppInfo(
                    display_name=f"Python ({p.name})",
                    version=ver_str,
                    version_tuple=self._parse_version(ver_str),
                    install_location=str(p),
                    uninstall_string="",
                    quiet_uninstall_string="",
                    registry_root="",
                    registry_key="",
                    is_disk_only=True
                ))
        return found

    def detect_duplicate_versions(self, progress_callback: Optional[Callable[[str], None]] = None) -> List[DuplicateAppGroup]:
        """
        Scans for applications that have multiple versions installed concurrently.
        Returns groups where older versions can be safely purged.
        """
        if progress_callback:
            progress_callback("Scanning installed software for duplicate and multi-version installations...")

        reg_apps = self.get_installed_apps_from_registry()
        disk_pythons = self.scan_disk_pythons()

        # Group apps by normalized name
        groups: Dict[str, List[InstalledAppInfo]] = {}

        for app in reg_apps:
            base = self._normalize_app_name(app.display_name).lower()
            if len(base) >= 3:
                groups.setdefault(base, []).append(app)

        # Check Python specifically combining disk + registry
        if len(disk_pythons) > 1:
            disk_pythons.sort(key=lambda a: a.version_tuple, reverse=True)
            groups["python (disk)"] = disk_pythons

        duplicates: List[DuplicateAppGroup] = []

        for base_name, app_list in groups.items():
            if len(app_list) <= 1:
                continue

            # Check if this group has genuinely different versions
            # Filter out identical versions (e.g. x86 and x64 of exact same runtime version)
            sorted_apps = sorted(app_list, key=lambda a: a.version_tuple, reverse=True)
            latest = sorted_apps[0]

            older_versions: List[InstalledAppInfo] = []
            for app in sorted_apps[1:]:
                # If version tuple is strictly smaller and not (0,)
                if app.version_tuple < latest.version_tuple and app.version_tuple != (0,):
                    older_versions.append(app)
                elif app.version and latest.version and app.version != latest.version:
                    older_versions.append(app)

            if older_versions:
                duplicates.append(DuplicateAppGroup(
                    base_name=latest.display_name.split()[0] if latest.display_name else base_name,
                    latest_app=latest,
                    older_apps=older_versions
                ))

        return duplicates

    def uninstall_older_version(self, app: InstalledAppInfo, progress_callback: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
        """Attempts to remove an older version of an application cleanly."""
        # 1. If it has a quiet or regular uninstall command
        cmd_to_run = app.quiet_uninstall_string or app.uninstall_string
        if cmd_to_run:
            if progress_callback:
                progress_callback(f"Launching uninstaller for {app.display_name}...")
            try:
                # Handle MsiExec /X{GUID}
                if "msiexec" in cmd_to_run.lower() and "/qn" not in cmd_to_run.lower():
                    cmd_to_run = f"{cmd_to_run} /qn /norestart"

                res = subprocess.run(cmd_to_run, shell=True, check=False)
                if res.returncode in (0, 3010):  # 3010 = reboot required, successful
                    return True, f"Successfully uninstalled {app.display_name}."
                return False, f"Uninstaller returned exit code {res.returncode}."
            except Exception as e:
                return False, f"Failed to execute uninstaller: {e}"

        # 2. If it's a disk-only folder (e.g. old Python directory)
        if app.is_disk_only and app.install_location:
            p = Path(app.install_location)
            if p.exists() and p.is_dir() and "python" in p.name.lower():
                try:
                    shutil.rmtree(p)
                    return True, f"Purged old installation directory: {p}"
                except Exception as e:
                    return False, f"Could not remove directory {p}: {e}"

        return False, "No valid uninstall string or directory found."
