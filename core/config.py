"""
Configuration Management for SysCare
Handles loading, saving, and updating user customization in config.json.
"""

import json
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    # Junk & Privacy Cleanup Toggles
    "clean_user_temp": True,
    "clean_system_temp": True,
    "clean_crash_dumps": True,
    "clean_recent_docs": True,
    "clean_explorer_history": True,
    "clean_browser_caches": True,
    "clean_dev_caches": True,
    "clean_app_leftovers": True,
    "clean_recycle_bin": True,
    "flush_dns": True,

    # Registry Cleanup Toggles
    "registry_clean_uninstall_leftovers": True,
    "registry_clean_broken_startup": True,
    "registry_clean_missing_app_paths": True,
    "registry_clean_stale_openwith": True,
    "registry_clean_mui_cache": True,

    # App Updater Toggles
    "update_apps_winget": True,

    # Environment & Services Toggles
    "clean_stale_env_paths": True,

    # Safety & Workflow
    "confirm_before_clean": True,

    # Exclusions
    "exclusions": {
        "directories": [],
        "registry_keys": []
    }
}

CONFIG_DESCRIPTIONS: Dict[str, str] = {
    "clean_user_temp": "Clean user temp folder (%TEMP%)",
    "clean_system_temp": "Clean Windows temp folder (C:\\Windows\\Temp - requires admin)",
    "clean_crash_dumps": "Clean crash dumps and Windows Error Reporting logs",
    "clean_recent_docs": "Clear recent documents history & JumpLists",
    "clean_explorer_history": "Clear Run dialog history, TypedPaths & search history",
    "clean_browser_caches": "Clear safe browser caches (Chrome, Edge, Brave, Firefox - no logins/cookies)",
    "clean_dev_caches": "Clean developer caches (pip, npm, nuget cache)",
    "clean_app_leftovers": "Scan & remove orphaned AppData folders from uninstalled apps",
    "clean_recycle_bin": "Empty Recycle Bin",
    "flush_dns": "Flush DNS resolver cache (ipconfig /flushdns)",
    "registry_clean_uninstall_leftovers": "Remove orphaned uninstalled app registry keys",
    "registry_clean_broken_startup": "Remove startup entries pointing to missing files",
    "registry_clean_missing_app_paths": "Remove App Paths pointing to missing files",
    "registry_clean_stale_openwith": "Clean dead FileExts / OpenWith associations",
    "registry_clean_mui_cache": "Clean stale shell MuiCache references",
    "update_apps_winget": "Update outdated apps via winget during All-in-One clean",
    "clean_stale_env_paths": "Clean stale and duplicate PATH entries from Environment variables",
    "confirm_before_clean": "Ask for confirmation after scan preview before cleaning"
}


class ConfigManager:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.data: Dict[str, Any] = self.load()

    def load(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            self.data = json.loads(json.dumps(DEFAULT_CONFIG))
            self.save()
            return self.data
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            # Merge with defaults in case of missing keys
            merged = json.loads(json.dumps(DEFAULT_CONFIG))
            merged.update(loaded)
            if "exclusions" not in merged:
                merged["exclusions"] = {"directories": [], "registry_keys": []}
            return merged
        except Exception:
            return json.loads(json.dumps(DEFAULT_CONFIG))

    def save(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=4)

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.data[key] = value
        self.save()

    def toggle(self, key: str) -> bool:
        if key in self.data and isinstance(self.data[key], bool):
            self.data[key] = not self.data[key]
            self.save()
            return self.data[key]
        return False

    def is_excluded_directory(self, path_str: str) -> bool:
        norm_path = path_str.lower().replace("/", "\\")
        for excluded in self.data.get("exclusions", {}).get("directories", []):
            if excluded.lower().replace("/", "\\") in norm_path:
                return True
        return False

    def is_excluded_registry(self, reg_path: str) -> bool:
        norm_key = reg_path.lower()
        for excluded in self.data.get("exclusions", {}).get("registry_keys", []):
            if excluded.lower() in norm_key:
                return True
        return False
