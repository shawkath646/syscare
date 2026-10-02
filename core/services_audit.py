"""
Windows Services Auditor for SysCare
Audits Windows Services in HKLM\\SYSTEM\\CurrentControlSet\\Services.
Detects orphaned services whose target binaries no longer exist on disk (left behind by uninstalled software).
Provides safe inspection, disabling, and deletion with single registry backup protection.
"""

import os
import re
import subprocess
import winreg
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from core.safety import RegistryBackupManager


START_TYPE_MAP: Dict[int, str] = {
    0: "Boot",
    1: "System",
    2: "Automatic",
    3: "Manual",
    4: "Disabled",
}


@dataclass
class ServiceInfo:
    name: str
    display_name: str
    image_path: str
    resolved_path: str
    start_type_code: int
    start_type_str: str
    service_type: int
    is_orphaned: bool = False
    is_disabled: bool = False
    reason: str = ""


@dataclass
class ServicesAuditReport:
    total_scanned: int = 0
    orphaned_services: List[ServiceInfo] = field(default_factory=list)
    disabled_services: List[ServiceInfo] = field(default_factory=list)
    healthy_services_count: int = 0


class ServicesAuditor:
    """Scans and audits Windows Services for orphaned entries and configuration issues."""

    SERVICES_REG_PATH = r"SYSTEM\CurrentControlSet\Services"

    # Core Windows system binaries that should never be treated as missing
    WHITELISTED_BINARIES = {
        "svchost.exe",
        "services.exe",
        "lsass.exe",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "rundll32.exe",
        "dllhost.exe",
        "explorer.exe",
    }

    def __init__(self, backup_mgr: RegistryBackupManager, admin_status: bool = False):
        self.backup_mgr = backup_mgr
        self.admin_status = admin_status

    def _resolve_image_path(self, raw_path: str) -> str:
        """Resolves raw ImagePath into a concrete file path on disk."""
        if not raw_path:
            return ""

        s = raw_path.strip()

        # Handle NT device prefixes: \??\
        if s.startswith("\\??\\"):
            s = s[4:]
        elif s.startswith("\\??/"):
            s = s[4:]

        sysroot = os.environ.get("SystemRoot", "C:\\Windows")
        if s.lower().startswith("\\systemroot\\"):
            s = os.path.join(sysroot, s[12:])
        elif s.lower().startswith("system32\\"):
            s = os.path.join(sysroot, s)

        # 1. Quoted path: "C:\Program Files\Vendor\service.exe" /run
        if s.startswith('"'):
            end_quote = s.find('"', 1)
            if end_quote != -1:
                return os.path.expandvars(s[1:end_quote].strip())
            s = s.strip('"')

        # 2. Test full string with expanded vars
        exp = os.path.expandvars(s)
        if os.path.exists(exp):
            return exp

        # 3. Regex match common extensions: .exe, .sys, .dll
        ext_match = re.match(r"^(.*?\.(?:exe|sys|dll))(?:\s+.*)?$", s, re.IGNORECASE)
        if ext_match:
            candidate = os.path.expandvars(ext_match.group(1).strip())
            if os.path.exists(candidate):
                return candidate

        # 4. Progressive space accumulation for unquoted paths with spaces
        parts = s.split()
        accum = ""
        for p in parts:
            accum = f"{accum} {p}".strip()
            exp_accum = os.path.expandvars(accum)
            if os.path.exists(exp_accum):
                return exp_accum
            if os.path.exists(f"{exp_accum}.exe"):
                return f"{exp_accum}.exe"

        # Fallback to first token
        first_token = parts[0].strip('"') if parts else s
        return os.path.expandvars(first_token)

    def _target_exists(self, file_path: str) -> bool:
        """Verifies if the target binary exists on disk, checking drivers and system32."""
        if not file_path:
            return True  # Avoid false positives if path cannot be parsed

        base = os.path.basename(file_path).lower()
        if base in self.WHITELISTED_BINARIES:
            return True

        expanded = os.path.expandvars(file_path)
        try:
            p = Path(expanded)
            if p.exists():
                return True
            if not p.suffix and p.with_suffix(".exe").exists():
                return True

            # Check inside System32
            sysroot = Path(os.environ.get("SystemRoot", "C:\\Windows"))
            if (sysroot / "System32" / expanded).exists():
                return True
            # Check inside System32\drivers for driver files
            if (sysroot / "System32" / "drivers" / base).exists():
                return True
        except Exception:
            return True

        return False

    def scan(self, progress_callback: Optional[Callable[[str], None]] = None) -> ServicesAuditReport:
        """Scans all registered Windows services and identifies orphaned or disabled ones."""
        report = ServicesAuditReport()

        if progress_callback:
            progress_callback("Accessing Windows Services registry hive...")

        try:
            services_root = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, self.SERVICES_REG_PATH, 0, winreg.KEY_READ
            )
        except Exception as e:
            if progress_callback:
                progress_callback(f"Failed to open Services registry key: {e}")
            return report

        total_keys, _, _ = winreg.QueryInfoKey(services_root)
        report.total_scanned = total_keys

        for i in range(total_keys):
            try:
                sub_name = winreg.EnumKey(services_root, i)
            except OSError:
                continue

            try:
                with winreg.OpenKey(services_root, sub_name, 0, winreg.KEY_READ) as svc_key:
                    # Read DisplayName
                    try:
                        disp_name, _ = winreg.QueryValueEx(svc_key, "DisplayName")
                        disp_name = str(disp_name).strip()
                    except OSError:
                        disp_name = sub_name

                    # Read ImagePath
                    try:
                        img_path, _ = winreg.QueryValueEx(svc_key, "ImagePath")
                        img_path = str(img_path).strip()
                    except OSError:
                        img_path = ""

                    # Read Start type
                    try:
                        start_code, _ = winreg.QueryValueEx(svc_key, "Start")
                        start_code = int(start_code)
                    except (OSError, ValueError):
                        start_code = 3  # Manual default

                    # Read Service Type
                    try:
                        svc_type, _ = winreg.QueryValueEx(svc_key, "Type")
                        svc_type = int(svc_type)
                    except (OSError, ValueError):
                        svc_type = 0

                    resolved = self._resolve_image_path(img_path)

                    # If svchost service, verify ServiceDll in Parameters subkey
                    if "svchost.exe" in resolved.lower():
                        try:
                            with winreg.OpenKey(svc_key, "Parameters", 0, winreg.KEY_READ) as param_key:
                                sdll, _ = winreg.QueryValueEx(param_key, "ServiceDll")
                                resolved_dll = self._resolve_image_path(str(sdll))
                                if resolved_dll:
                                    resolved = resolved_dll
                        except OSError:
                            pass

                    is_disabled = (start_code == 4)
                    is_orphaned = False
                    reason = ""

                    # Only flag services that actually define an ImagePath or ServiceDll
                    if img_path:
                        exists = self._target_exists(resolved)
                        if not exists:
                            is_orphaned = True
                            reason = f"Executable missing on disk: {resolved}"

                    start_str = START_TYPE_MAP.get(start_code, f"Unknown ({start_code})")

                    svc_info = ServiceInfo(
                        name=sub_name,
                        display_name=disp_name,
                        image_path=img_path,
                        resolved_path=resolved,
                        start_type_code=start_code,
                        start_type_str=start_str,
                        service_type=svc_type,
                        is_orphaned=is_orphaned,
                        is_disabled=is_disabled,
                        reason=reason,
                    )

                    if is_orphaned:
                        report.orphaned_services.append(svc_info)
                    elif is_disabled:
                        report.disabled_services.append(svc_info)
                    else:
                        report.healthy_services_count += 1

            except Exception:
                continue

        winreg.CloseKey(services_root)
        return report

    def delete_orphaned_service(
        self,
        service: ServiceInfo,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Tuple[bool, str]:
        """
        Safely deletes an orphaned service from Windows.
        Enforces single registry backup of the service key before deletion.
        """
        if not self.admin_status:
            return False, "Administrator privileges are required to remove Windows services."

        # Step 1: Backup service registry key via reg.exe export
        full_key = f"HKLM\\{self.SERVICES_REG_PATH}\\{service.name}"
        if progress_callback:
            progress_callback(f"Backing up service registry key: {service.name}...")

        backup_file = self.backup_mgr.backup_whole_key_tree("HKLM", f"{self.SERVICES_REG_PATH}\\{service.name}")

        # Step 2: Use sc.exe delete to delete the service properly from SCM
        if progress_callback:
            progress_callback(f"Running 'sc.exe delete {service.name}'...")

        try:
            res = subprocess.run(
                ["sc.exe", "delete", service.name],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if res.returncode == 0 or "marked for deletion" in res.stdout.lower() or "SUCCESS" in res.stdout:
                bk_msg = f" (Backup saved: {backup_file.name})" if backup_file else ""
                return True, f"Service '{service.name}' successfully deleted.{bk_msg}"
        except Exception:
            pass

        # Step 3: Fallback - remove registry key directly via reg.exe delete if sc fails
        try:
            del_res = subprocess.run(
                ["reg.exe", "delete", full_key, "/f"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if del_res.returncode == 0:
                bk_msg = f" (Backup saved: {backup_file.name})" if backup_file else ""
                return True, f"Service '{service.name}' removed from registry.{bk_msg}"
        except Exception as e:
            return False, f"Failed to remove service '{service.name}': {e}"

        return False, f"Could not delete service '{service.name}'. It may be locked by Windows."

    def disable_service(
        self,
        service: ServiceInfo,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Tuple[bool, str]:
        """Disables a service via sc.exe config start= disabled."""
        if not self.admin_status:
            return False, "Administrator privileges are required to configure Windows services."

        try:
            res = subprocess.run(
                ["sc.exe", "config", service.name, "start=", "disabled"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if res.returncode == 0 or "SUCCESS" in res.stdout:
                return True, f"Service '{service.name}' startup type changed to Disabled."
            return False, f"Failed to disable service: {res.stdout.strip() or res.stderr.strip()}"
        except Exception as e:
            return False, f"Error disabling service '{service.name}': {e}"
