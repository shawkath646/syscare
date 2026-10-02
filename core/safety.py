"""
Safety and Rollback Management for SysCare
- Administrative privilege detection and UAC relaunch
- Single-file Registry Backup & Restore manager (automatically deletes previous backup before creating new one)
"""

import ctypes
import os
import subprocess
import sys
import winreg
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union


def is_admin() -> bool:
    """Checks if the current process is running with Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def check_running_apps() -> List[str]:
    """Scans running processes for active third-party apps that should be closed before cleaning."""
    common_apps = {
        "chrome.exe": "Google Chrome",
        "msedge.exe": "Microsoft Edge",
        "firefox.exe": "Mozilla Firefox",
        "brave.exe": "Brave Browser",
        "opera.exe": "Opera",
        "code.exe": "Visual Studio Code",
        "discord.exe": "Discord",
        "telegram.exe": "Telegram",
        "slack.exe": "Slack",
        "teams.exe": "Microsoft Teams",
        "spotify.exe": "Spotify",
        "steam.exe": "Steam",
        "epicgameslauncher.exe": "Epic Games Launcher",
        "notepad++.exe": "Notepad++",
    }
    detected = set()
    try:
        import csv
        import io
        res = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            reader = csv.reader(io.StringIO(res.stdout))
            for row in reader:
                if row:
                    p_name = row[0].strip().lower()
                    if p_name in common_apps:
                        detected.add(common_apps[p_name])
    except Exception:
        pass
    return sorted(detected)


def relaunch_as_admin(args: Optional[List[str]] = None) -> bool:
    """Relaunches the current Python script or standalone executable with elevated Administrator privileges."""
    if args is None:
        args = sys.argv[1:]

    is_frozen = getattr(sys, "frozen", False)
    if is_frozen:
        exe = sys.executable
        params = " ".join(f'"{a}"' for a in args)
    else:
        exe = sys.executable
        params = f'"{sys.argv[0]}" ' + " ".join(f'"{a}"' for a in args)

    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            exe,
            params,
            None,
            1  # SW_SHOWNORMAL
        )
        return ret > 32
    except Exception:
        return False


class RegistryBackupItem:
    """Represents a registry item (key or value) to be backed up before deletion."""
    def __init__(self, root: str, subkey: str, value_name: Optional[str] = None,
                 value_type: Optional[int] = None, value_data: Optional[Union[str, int, bytes]] = None):
        self.root = root                  # "HKCU" or "HKLM"
        self.subkey = subkey              # e.g. "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        self.value_name = value_name      # None if backing up entire key
        self.value_type = value_type      # winreg.REG_SZ, winreg.REG_DWORD, etc.
        self.value_data = value_data      # Original value


class RegistryBackupManager:
    """
    Manages the single active registry backup.
    Ensures that only ONE backup exists at any time.
    Whenever a new backup is requested, any existing backup file is deleted first.
    """

    BACKUP_FILENAME = "syscare_registry_latest.reg"

    def __init__(self, backup_dir: Path):
        self.backup_dir = backup_dir
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.latest_backup_path = self.backup_dir / self.BACKUP_FILENAME

    def purge_previous_backups(self) -> int:
        """Deletes any existing .reg backups to ensure only a single backup ever exists."""
        deleted_count = 0
        try:
            for reg_file in self.backup_dir.glob("*.reg"):
                try:
                    reg_file.unlink()
                    deleted_count += 1
                except Exception:
                    pass
        except Exception:
            pass
        return deleted_count

    def get_existing_backup_info(self) -> Optional[Dict[str, Union[str, int, datetime]]]:
        """Returns details about the current single backup if it exists."""
        if not self.latest_backup_path.exists():
            return None
        try:
            st = self.latest_backup_path.stat()
            return {
                "path": self.latest_backup_path,
                "size_bytes": st.st_size,
                "modified_time": datetime.fromtimestamp(st.st_mtime),
                "modified_str": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception:
            return None

    def create_backup(self, items_to_delete: List[RegistryBackupItem]) -> Optional[Path]:
        """
        1. Purges previous backup file (strict single-backup policy).
        2. Exports keys / values into syscare_registry_latest.reg.
        """
        # Enforce single backup rule
        self.purge_previous_backups()

        if not items_to_delete:
            return None

        content_lines = [
            "Windows Registry Editor Version 5.00",
            f"; SysCare Automated Registry Backup created on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "; Restoring this file will re-insert the registry keys and values that were cleaned.",
            ""
        ]

        # Separate whole key exports from individual value items
        whole_keys: Set[str] = set()
        val_items: List[RegistryBackupItem] = []
        for item in items_to_delete:
            full_key_name = self._expand_root(item.root) + "\\" + item.subkey
            if item.value_name is None:
                whole_keys.add(full_key_name)
            else:
                val_items.append(item)

        # 1. Export whole keys using Windows reg.exe export
        import tempfile
        for full_key in whole_keys:
            try:
                temp_reg = tempfile.NamedTemporaryFile(suffix=".reg", delete=False)
                temp_reg.close()
                res = subprocess.run(
                    ["reg.exe", "export", full_key, temp_reg.name, "/y"],
                    capture_output=True,
                    text=True,
                    check=False
                )
                if res.returncode == 0:
                    try:
                        # Try reading utf-16 le (default for reg export)
                        with open(temp_reg.name, "r", encoding="utf-16le", errors="replace") as rf:
                            raw_lines = rf.readlines()
                    except Exception:
                        with open(temp_reg.name, "r", encoding="utf-8", errors="replace") as rf:
                            raw_lines = rf.readlines()

                    # Filter out header from sub-export and append
                    for rl in raw_lines:
                        line_stripped = rl.strip()
                        if line_stripped.startswith("Windows Registry Editor") or not line_stripped:
                            continue
                        content_lines.append(line_stripped)
                    content_lines.append("")
                try:
                    os.unlink(temp_reg.name)
                except Exception:
                    pass
            except Exception:
                pass

        # 2. Group individual value items by key
        grouped: Dict[str, List[RegistryBackupItem]] = {}
        for item in val_items:
            full_key_name = self._expand_root(item.root) + "\\" + item.subkey
            # Skip if whole key was already exported above
            if full_key_name not in whole_keys:
                grouped.setdefault(full_key_name, []).append(item)

        for full_key, items in grouped.items():
            content_lines.append(f"[{full_key}]")
            for item in items:
                reg_line = self._format_value_line(item.value_name, item.value_type, item.value_data)
                if reg_line:
                    content_lines.append(reg_line)
            content_lines.append("")

        try:
            with open(self.latest_backup_path, "w", encoding="utf-16", newline="\r\n") as f:
                f.write("\n".join(content_lines))
            return self.latest_backup_path
        except Exception:
            try:
                with open(self.latest_backup_path, "w", encoding="utf-8", newline="\r\n") as f:
                    f.write("\n".join(content_lines))
                return self.latest_backup_path
            except Exception:
                return None

    def restore_latest_backup(self) -> Tuple[bool, str]:
        """Restores the single registry backup via Windows reg.exe import."""
        if not self.latest_backup_path.exists():
            return False, "No previous backup found to restore."

        try:
            cmd = ["reg.exe", "import", str(self.latest_backup_path)]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode == 0:
                return True, f"Successfully restored registry from {self.latest_backup_path.name}."
            else:
                return False, f"Registry restore failed: {res.stderr.strip() or res.stdout.strip()}"
        except Exception as e:
            return False, f"Error launching reg.exe: {e}"

    @staticmethod
    def _expand_root(root: str) -> str:
        r = root.upper()
        if r in ("HKCU", "HKEY_CURRENT_USER"):
            return "HKEY_CURRENT_USER"
        if r in ("HKLM", "HKEY_LOCAL_MACHINE"):
            return "HKEY_LOCAL_MACHINE"
        if r in ("HKCR", "HKEY_CLASSES_ROOT"):
            return "HKEY_CLASSES_ROOT"
        return root

    @staticmethod
    def _format_value_line(name: str, vtype: Optional[int], data: Any) -> str:
        """Formats a key-value pair in standard .reg file format."""
        formatted_name = "@" if name == "" else f'"{name}"'

        if vtype == winreg.REG_SZ:
            safe_data = str(data).replace("\\", "\\\\").replace('"', '\\"')
            return f'{formatted_name}="{safe_data}"'
        elif vtype == winreg.REG_EXPAND_SZ:
            safe_data = str(data).replace("\\", "\\\\").replace('"', '\\"')
            return f'{formatted_name}=hex(2):' + ",".join(f"{b:02x}" for b in safe_data.encode("utf-16le") + b"\x00\x00")
        elif vtype == winreg.REG_DWORD:
            return f'{formatted_name}=dword:{int(data):08x}'
        elif vtype == winreg.REG_BINARY:
            if isinstance(data, (bytes, bytearray)):
                hex_str = ",".join(f"{b:02x}" for b in data)
            else:
                hex_str = ""
            return f"{formatted_name}=hex:{hex_str}"
        elif vtype == winreg.REG_MULTI_SZ:
            if isinstance(data, list):
                raw = ("\x00".join(data) + "\x00\x00").encode("utf-16le")
                return f"{formatted_name}=hex(7):" + ",".join(f"{b:02x}" for b in raw)
            return f'{formatted_name}=""'
        else:
            safe_data = str(data or "").replace("\\", "\\\\").replace('"', '\\"')
            return f'{formatted_name}="{safe_data}"'
