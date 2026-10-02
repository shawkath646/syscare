"""
SysCare - Personal Windows Care, Cleaner & Optimizer
Single-entry application featuring Auto Mode & Manual Mode, Multi-Version App Cleaner,
Smart AI-Style Process Guardian, and single-backup registry protection.
"""

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional

# Ensure project root is in sys.path and resolve portable root directory
if getattr(sys, "frozen", False):
    SCRIPT_DIR = Path(sys.executable).resolve().parent
else:
    SCRIPT_DIR = Path(__file__).resolve().parent

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from core import __version__
from core.app_duplicates import MultiVersionDetector
from core.app_updater import AppUpdater
from core.config import CONFIG_DESCRIPTIONS, ConfigManager
from core.console import (
    Colors,
    clear_screen,
    format_bytes,
    pause,
    print_banner,
    print_close_apps_warning,
    print_error,
    print_header,
    print_info,
    print_item,
    print_step,
    print_success,
    print_table,
    print_warning,
    prompt_choice,
    prompt_yes_no,
)
from core.junk_cleaner import JunkCleaner
from core.process_guardian import ProcessGuardian
from core.registry_cleaner import RegistryCleaner
from core.safety import RegistryBackupManager, check_running_apps, is_admin, relaunch_as_admin
from core.scheduler import WeeklyScheduler
from core.env_cleaner import EnvironmentCleaner
from core.event_log_viewer import EventLogViewer
from core.services_audit import ServicesAuditor


class SysCareApp:
    def __init__(self):
        self.root_dir = SCRIPT_DIR
        self.config_path = self.root_dir / "config.json"
        self.backup_dir = self.root_dir / "backups"

        self.config_mgr = ConfigManager(self.config_path)
        self.backup_mgr = RegistryBackupManager(self.backup_dir)
        self.admin_status = is_admin()

        self.junk_cleaner = JunkCleaner(self.config_mgr, self.admin_status)
        self.registry_cleaner = RegistryCleaner(self.config_mgr, self.backup_mgr, self.admin_status)
        self.app_updater = AppUpdater()
        self.scheduler = WeeklyScheduler(self.root_dir)
        self.multi_ver_detector = MultiVersionDetector()
        self.process_guardian = ProcessGuardian()
        self.env_cleaner = EnvironmentCleaner(self.backup_mgr, self.admin_status)
        self.event_log_viewer = EventLogViewer()
        self.services_auditor = ServicesAuditor(self.backup_mgr, self.admin_status)

    def check_and_warn_apps(self, skip_confirm: bool = False) -> bool:
        """Warns the user to close all third-party applications before proceeding with cleaning."""
        running = check_running_apps()
        print_close_apps_warning(running)
        if not skip_confirm:
            if not prompt_yes_no("Have you saved your work and closed other applications? Ready to proceed?", default=True):
                print_warning("Operation cancelled by user. Please close your applications and run SysCare again.")
                return False
        return True

    # -------------------------------------------------------------
    # AUTO MODE (ONE-CLICK COMPLETE SYSTEM CARE)
    # -------------------------------------------------------------
    def run_auto_mode(self, skip_confirm: bool = False) -> None:
        clear_screen()
        print_banner(self.admin_status, __version__)
        print_header("Auto Mode — One-Click Smart System Care")
        print_info("SysCare will perform complete automated maintenance with safety safeguards.")

        # Step 0: Pre-operation third party apps check
        if not self.check_and_warn_apps(skip_confirm=skip_confirm):
            return

        print_step(1, 6, "Cleaning Junk Files, Caches & Privacy History...")
        junk_report = self.junk_cleaner.clean_all(dry_run=False, progress_callback=print_info)
        print_success(f"Freed {format_bytes(junk_report.reclaimed_bytes)} across {junk_report.cleaned_files:,} files!")

        print_step(2, 6, "Scanning & Repairing Registry (Single-Backup Enforced)...")
        reg_scan = self.registry_cleaner.scan(progress_callback=print_info)
        if reg_scan.issues:
            reg_report = self.registry_cleaner.clean(reg_scan, progress_callback=print_info)
            if reg_report.backup_file:
                print_success(f"Single registry backup updated: {reg_report.backup_file.name}")
            print_success(f"Safely cleaned {reg_report.cleaned_count:,} broken registry entries!")
        else:
            print_success("Registry is already clean! No broken keys found.")

        print_step(3, 6, "Auditing Environment Variable PATH (Deduplicating & Cleaning Stale)...")
        if self.config_mgr.get("clean_stale_env_paths", True):
            env_scan = self.env_cleaner.scan(progress_callback=print_info)
            if env_scan.stale_count > 0 or env_scan.duplicate_count > 0:
                print_info(f"Found {env_scan.stale_count} stale and {env_scan.duplicate_count} duplicate PATH entries.")
                clean_env_rep = self.env_cleaner.clean(
                    env_scan,
                    clean_user=True,
                    clean_system=self.admin_status,
                    remove_stale=True,
                    remove_duplicates=True,
                    progress_callback=print_info,
                )
                print_success(f"Cleaned {clean_env_rep.cleaned_stale} stale entries and {clean_env_rep.cleaned_duplicates} duplicates from PATH!")
            else:
                print_success("Environment PATH is clean! No stale or duplicate paths found.")
        else:
            print_info("Environment PATH cleanup is disabled in settings.")

        print_step(4, 6, "Checking for Duplicate Multi-Version Applications...")
        dups = self.multi_ver_detector.detect_duplicate_versions(progress_callback=print_info)
        if dups:
            print_warning(f"Found {len(dups)} application(s) with multiple installed versions:")
            for d in dups:
                print(f"  • {Colors.BOLD}{d.base_name}{Colors.RESET}: Latest is {d.latest_app.display_name} (v{d.latest_app.version})")
                for old in d.older_apps:
                    print(f"    ↳ Older version: {old.display_name} (v{old.version})")
                    if skip_confirm or prompt_yes_no(f"    Uninstall older version '{old.display_name}'?", default=True):
                        ok, msg = self.multi_ver_detector.uninstall_older_version(old, progress_callback=print_info)
                        if ok:
                            print_success(msg)
                        else:
                            print_warning(msg)
        else:
            print_success("No duplicate or outdated multi-version apps detected.")

        print_step(5, 6, "Smart Process & Resource Health Guardian...")
        guard_rep = self.process_guardian.scan(progress_callback=print_info)
        if guard_rep.flagged_processes:
            print_warning(f"Process Guardian flagged {len(guard_rep.flagged_processes)} resource hog(s) / background task(s):")
            for p in guard_rep.flagged_processes:
                print(f"  • [{p.severity}] {p.name} (PID: {p.pid}) Mem: {p.mem_str} - {p.diagnosis}")
                if prompt_yes_no(f"    Terminate {p.name} (PID: {p.pid}) to reclaim {p.mem_str} RAM?", default=False):
                    ok, msg = self.process_guardian.terminate_process(p.pid)
                    if ok:
                        print_success(msg)
                    else:
                        print_error(msg)
        else:
            print_success("Process Guardian Health: OPTIMAL. No rogue processes or memory hogs detected.")

        print_step(6, 6, "Checking for Outdated Software via Winget...")
        if self.config_mgr.get("update_apps_winget", True) and self.app_updater.is_available():
            updates = self.app_updater.get_available_updates(progress_callback=print_info)
            if updates:
                print_info(f"Found {len(updates)} application update(s) available.")
                if skip_confirm or prompt_yes_no(f"Upgrade all {len(updates)} outdated application(s) now?", default=True):
                    self.app_updater.upgrade_all(interactive=True, progress_callback=print_info)
            else:
                print_success("All installed software is completely up-to-date!")

        print_header("Auto Mode Maintenance Completed")
        print_success(f"System fully refreshed! Total space reclaimed: {format_bytes(junk_report.reclaimed_bytes)}")

    # -------------------------------------------------------------
    # 1. ALL-IN-ONE CARE (MANUAL MODE)
    # -------------------------------------------------------------
    def run_all_in_one(self, skip_confirm: bool = False, scan_only: bool = False) -> None:
        print_header("All-in-One Care (Full System Maintenance)")
        print_info("Scanning junk files, privacy history, and broken registry entries...")

        junk_report = self.junk_cleaner.clean_all(dry_run=True, progress_callback=print_info)
        reg_report = self.registry_cleaner.scan(progress_callback=print_info)
        env_report = self.env_cleaner.scan(progress_callback=print_info)
        dups = self.multi_ver_detector.detect_duplicate_versions(progress_callback=print_info)

        updates = []
        if self.config_mgr.get("update_apps_winget", True) and self.app_updater.is_available():
            updates = self.app_updater.get_available_updates(progress_callback=print_info)

        print(f"\n{Colors.BOLD}--- SCAN SUMMARY ---{Colors.RESET}")
        print_item("Junk Files Found", f"{junk_report.total_files:,} items ({format_bytes(junk_report.total_bytes)})")
        print_item("Registry Issues Found", f"{len(reg_report.issues):,} broken / orphaned entries")
        print_item("Stale / Duplicate PATHs", f"{env_report.stale_count} stale, {env_report.duplicate_count} duplicates" if (env_report.stale_count or env_report.duplicate_count) else "All PATH entries valid")
        print_item("Multi-Version Apps", f"{len(dups)} duplicate app groups" if dups else "None detected")
        print_item("Software Updates", f"{len(updates)} available updates" if updates else "All software up-to-date")

        if scan_only:
            print_success("Scan completed (Dry-run mode). No changes were made.")
            return

        if not self.check_and_warn_apps(skip_confirm=skip_confirm):
            return

        if not skip_confirm and self.config_mgr.get("confirm_before_clean", True):
            if not prompt_yes_no("\nProceed with All-in-One Cleanup & Optimization?", default=True):
                print_warning("Operation cancelled by user.")
                return

        print_header("Cleaning Junk Files & System History")
        real_junk_report = self.junk_cleaner.clean_all(dry_run=False, progress_callback=print_info)
        print_success(f"Cleaned {real_junk_report.cleaned_files:,} files, reclaimed {format_bytes(real_junk_report.reclaimed_bytes)} disk space!")

        if reg_report.issues:
            print_header("Repairing Registry")
            print_info("Enforcing single backup: any previous registry backup will be replaced...")
            real_reg_report = self.registry_cleaner.clean(reg_report, progress_callback=print_info)
            if real_reg_report.backup_file:
                print_success(f"Single backup saved: {real_reg_report.backup_file.name}")
            print_success(f"Safely cleaned {real_reg_report.cleaned_count:,} broken registry entries!")

        if (env_report.stale_count or env_report.duplicate_count) and self.config_mgr.get("clean_stale_env_paths", True):
            print_header("Cleaning Environment PATH Entries")
            clean_env_rep = self.env_cleaner.clean(
                env_report,
                clean_user=True,
                clean_system=self.admin_status,
                remove_stale=True,
                remove_duplicates=True,
                progress_callback=print_info,
            )
            print_success(f"Cleaned {clean_env_rep.cleaned_stale} stale entries and {clean_env_rep.cleaned_duplicates} duplicates from PATH!")

        if dups:
            print_header("Duplicate Multi-Version Applications")
            for d in dups:
                print(f"  • {d.base_name}: Latest is {d.latest_app.display_name}")
                for old in d.older_apps:
                    if prompt_yes_no(f"    Uninstall older version '{old.display_name}'?", default=True):
                        ok, msg = self.multi_ver_detector.uninstall_older_version(old, progress_callback=print_info)
                        if ok: print_success(msg)
                        else: print_warning(msg)

        if updates and self.config_mgr.get("update_apps_winget", True):
            print_header("Updating Applications")
            if skip_confirm or prompt_yes_no(f"Update {len(updates)} outdated application(s) now?", default=True):
                self.app_updater.upgrade_all(interactive=True, progress_callback=print_info)

        print_header("All-in-One Care Completed")
        print_success(f"System refreshed! Total space freed: {format_bytes(real_junk_report.reclaimed_bytes)}")

    # -------------------------------------------------------------
    # 2. UPDATE APPS (WITH PRE-UPDATE MULTI-VERSION SCAN)
    # -------------------------------------------------------------
    def run_update_apps(self) -> None:
        print_header("Application Updater & Version Manager")

        # Step 1: Pre-update check for duplicate multi-version apps
        print_info("Checking for co-existing multi-version applications (e.g. Python 2/3, old SDKs)...")
        dups = self.multi_ver_detector.detect_duplicate_versions()
        if dups:
            print_warning(f"Found {len(dups)} application(s) with older co-existing versions installed:")
            for d in dups:
                print(f"\n  {Colors.BOLD}Product: {d.base_name}{Colors.RESET}")
                print(f"    {Colors.BRIGHT_GREEN}Latest installed:{Colors.RESET} {d.latest_app.display_name} (v{d.latest_app.version})")
                for old in d.older_apps:
                    print(f"    {Colors.BRIGHT_YELLOW}Older version:{Colors.RESET}    {old.display_name} (v{old.version})")
                    if prompt_yes_no(f"    Uninstall older version '{old.display_name}' before proceeding?", default=True):
                        ok, msg = self.multi_ver_detector.uninstall_older_version(old, progress_callback=print_info)
                        if ok:
                            print_success(msg)
                        else:
                            print_warning(msg)
        else:
            print_success("No duplicate or older multi-version apps found.")

        # Step 2: Scan for outdated apps via Winget
        if not self.app_updater.is_available():
            print_error("Winget package manager is not installed on this system.")
            return

        updates = self.app_updater.get_available_updates(progress_callback=print_info)
        if not updates:
            print_success("All installed applications are up-to-date!")
            return

        headers = ["#", "Application Name", "ID", "Current", "Available"]
        rows = [
            [str(i + 1), u.name[:30], u.id[:25], u.current_version, u.available_version]
            for i, u in enumerate(updates)
        ]
        print(f"\n{Colors.BOLD}Available Updates ({len(updates)}):{Colors.RESET}")
        print_table(headers, rows)

        print(f"\n{Colors.CYAN}[1]{Colors.RESET} Update All Applications")
        print(f"{Colors.CYAN}[2]{Colors.RESET} Update Single Application by #")
        print(f"{Colors.CYAN}[0]{Colors.RESET} Return to Main Menu")

        choice = prompt_choice("Select an action", ["1", "2", "0"])
        if choice == "1":
            print_info("Launching winget upgrade --all...")
            self.app_updater.upgrade_all(interactive=True)
        elif choice == "2":
            idx_str = input(f"Enter package number (1-{len(updates)}): ").strip()
            if idx_str.isdigit() and 1 <= int(idx_str) <= len(updates):
                pkg = updates[int(idx_str) - 1]
                print_info(f"Updating {pkg.name} ({pkg.id})...")
                self.app_updater.upgrade_package(pkg.id, interactive=True)
            else:
                print_error("Invalid package number.")

    # -------------------------------------------------------------
    # 3. JUNK CLEANUP
    # -------------------------------------------------------------
    def run_junk_cleanup(self, skip_confirm: bool = False, scan_only: bool = False) -> None:
        print_header("Junk & Privacy History Cleanup")
        print_info("Scanning temporary files, recent documents, search history, browser caches...")

        report = self.junk_cleaner.clean_all(dry_run=True)

        headers = ["Category", "Items Found", "Space Found"]
        rows = []
        for cat, stat in report.categories.items():
            rows.append([cat, f"{stat['found_items']:,}", format_bytes(stat["found_bytes"])])

        print(f"\n{Colors.BOLD}Junk Scan Results:{Colors.RESET}")
        print_table(headers, rows)
        print(f"\n{Colors.BOLD}Total Space to Reclaim:{Colors.RESET} {Colors.BRIGHT_GREEN}{format_bytes(report.total_bytes)}{Colors.RESET}")

        if scan_only:
            print_success("Scan completed. No files were removed.")
            return

        if not self.check_and_warn_apps(skip_confirm=skip_confirm):
            return

        if not skip_confirm:
            if not prompt_yes_no("\nProceed with cleaning these items?", default=True):
                print_warning("Cleanup cancelled.")
                return

        print_info("Cleaning files and refreshing history...")
        real_report = self.junk_cleaner.clean_all(dry_run=False, progress_callback=print_info)
        print_success(f"Cleanup finished! Removed {real_report.cleaned_files:,} items, freed {format_bytes(real_report.reclaimed_bytes)}.")

    # -------------------------------------------------------------
    # 4. REGISTRY CLEANUP (WITH SINGLE BACKUP ENFORCEMENT)
    # -------------------------------------------------------------
    def run_registry_cleanup(self, skip_confirm: bool = False, scan_only: bool = False) -> None:
        print_header("Registry Cleanup & Repair")
        print_info("Scanning for orphaned uninstalled software entries, dead startup items, stale file associations...")

        report = self.registry_cleaner.scan(progress_callback=print_info)

        if not report.issues:
            print_success("Registry is clean! No broken or orphaned entries found.")
            return

        headers = ["Category", "Issues Found"]
        rows = [[cat, f"{count:,}"] for cat, count in report.categories_count.items()]
        print(f"\n{Colors.BOLD}Registry Scan Results ({len(report.issues)} total issues):{Colors.RESET}")
        print_table(headers, rows)

        print(f"\n{Colors.BOLD}Sample issues found:{Colors.RESET}")
        for issue in report.issues[:5]:
            print(f"  {Colors.GRAY}•{Colors.RESET} [{issue.category}] {issue.reason}")
        if len(report.issues) > 5:
            print(f"  {Colors.GRAY}... and {len(report.issues) - 5} more items.{Colors.RESET}")

        if scan_only:
            print_success("Scan completed. Registry remains unchanged.")
            return

        if not self.check_and_warn_apps(skip_confirm=skip_confirm):
            return

        existing_backup = self.backup_mgr.get_existing_backup_info()
        if existing_backup:
            print_warning(f"Note: A previous backup exists from {existing_backup['modified_str']}.")
            print_info("Per single-backup policy, it will be automatically replaced with a new backup before changes.")

        if not skip_confirm:
            if not prompt_yes_no("\nProceed with registry repair?", default=True):
                print_warning("Registry repair cancelled.")
                return

        print_info("Enforcing single backup and applying fixes...")
        cleaned_report = self.registry_cleaner.clean(report, progress_callback=print_info)

        if cleaned_report.backup_file:
            print_success(f"Single registry backup updated: {cleaned_report.backup_file}")
        print_success(f"Successfully cleaned {cleaned_report.cleaned_count:,} broken registry entries!")

    # -------------------------------------------------------------
    # 5. MULTI-VERSION APP MANAGER
    # -------------------------------------------------------------
    def run_multi_version_manager(self) -> None:
        print_header("Multi-Version Installed App Manager")
        print_info("Scanning for multiple concurrently installed versions of software...")

        dups = self.multi_ver_detector.detect_duplicate_versions(progress_callback=print_info)
        if not dups:
            print_success("No duplicate or multi-version applications found!")
            return

        for i, d in enumerate(dups):
            print(f"\n{Colors.CYAN}[{i + 1}] {Colors.BOLD}{d.base_name}{Colors.RESET}")
            print(f"    {Colors.BRIGHT_GREEN}Latest:{Colors.RESET} {d.latest_app.display_name} (v{d.latest_app.version})")
            for old in d.older_apps:
                print(f"    {Colors.BRIGHT_YELLOW}Older:{Colors.RESET}  {old.display_name} (v{old.version})")
                if prompt_yes_no(f"    Uninstall {old.display_name}?", default=True):
                    ok, msg = self.multi_ver_detector.uninstall_older_version(old, progress_callback=print_info)
                    if ok: print_success(msg)
                    else: print_error(msg)

    # -------------------------------------------------------------
    # 6. SMART PROCESS & RESOURCE HEALTH GUARDIAN
    # -------------------------------------------------------------
    def run_process_guardian(self) -> None:
        print_header("Smart Process & Resource Health Guardian")
        print_info("Running AI-style heuristic scan across running processes...")

        rep = self.process_guardian.scan(progress_callback=print_info)

        print(f"\n{Colors.BOLD}Process Guardian Status: {Colors.RESET}", end="")
        if rep.system_health_status == "OPTIMAL":
            print(f"{Colors.BRIGHT_GREEN}[OPTIMAL - SYSTEM HEALTHY]{Colors.RESET}")
        elif rep.system_health_status == "MODERATE":
            print(f"{Colors.BRIGHT_YELLOW}[MODERATE - RESOURCE HOGS DETECTED]{Colors.RESET}")
        else:
            print(f"{Colors.BRIGHT_RED}[ALERT - SUSPICIOUS BEHAVIOR DETECTED]{Colors.RESET}")

        print_item("Processes Scanned", f"{rep.total_processes_scanned:,}")
        print_item("Flagged Concerns", f"{len(rep.flagged_processes)}")
        if rep.total_hog_memory_bytes > 0:
            print_item("Memory Used by Hogs", format_bytes(rep.total_hog_memory_bytes))

        if not rep.flagged_processes:
            print_success("\nAll processes running within normal parameters! No suspicious behavior or memory hogs found.")
            return

        headers = ["PID", "Process Name", "Severity", "Memory", "Diagnosis"]
        rows = [
            [str(p.pid), p.name[:20], p.severity, p.mem_str, p.diagnosis[:35]]
            for p in rep.flagged_processes
        ]
        print(f"\n{Colors.BOLD}Flagged Processes:{Colors.RESET}")
        print_table(headers, rows)

        for p in rep.flagged_processes:
            print(f"\n{Colors.BOLD}Process Details: {p.name} (PID: {p.pid}){Colors.RESET}")
            print_item("Path", p.path or "(not available)")
            print_item("Memory", p.mem_str)
            print_item("Diagnosis", p.diagnosis)
            print_item("Recommendation", p.recommendation)
            if prompt_yes_no(f"Terminate PID {p.pid} ({p.name})?", default=False):
                ok, msg = self.process_guardian.terminate_process(p.pid)
                if ok: print_success(msg)
                else: print_error(msg)

    # -------------------------------------------------------------
    # 7. CUSTOMIZATION & SETTINGS
    # -------------------------------------------------------------
    def run_settings(self) -> None:
        while True:
            clear_screen()
            print_banner(self.admin_status, __version__)
            print_header("Customization & Settings")
            print_info("Toggle features on/off or manage exclusions. Changes take effect immediately.")

            keys = list(CONFIG_DESCRIPTIONS.keys())
            headers = ["#", "Feature / Setting", "Status"]
            rows = []
            for i, k in enumerate(keys):
                val = self.config_mgr.get(k, True)
                status_str = f"{Colors.BRIGHT_GREEN}[ENABLED]{Colors.RESET}" if val else f"{Colors.GRAY}[DISABLED]{Colors.RESET}"
                desc = CONFIG_DESCRIPTIONS.get(k, k)
                rows.append([str(i + 1), desc, status_str])

            print_table(headers, rows)

            print(f"\n{Colors.CYAN}[#]{Colors.RESET} Enter number (1-{len(keys)}) to toggle")
            print(f"{Colors.CYAN}[D]{Colors.RESET} Reset to Recommended Defaults")
            print(f"{Colors.CYAN}[0]{Colors.RESET} Return to Manual Menu")

            choice = input(f"\n{Colors.BRIGHT_CYAN}> Choose an option:{Colors.RESET} ").strip()
            if choice == "0":
                break
            elif choice.upper() == "D":
                from core.config import DEFAULT_CONFIG
                import json
                self.config_mgr.data = json.loads(json.dumps(DEFAULT_CONFIG))
                self.config_mgr.save()
                print_success("Settings reset to recommended defaults.")
                pause()
            elif choice.isdigit() and 1 <= int(choice) <= len(keys):
                selected_key = keys[int(choice) - 1]
                new_state = self.config_mgr.toggle(selected_key)
                state_text = "ENABLED" if new_state else "DISABLED"
                print_info(f"Setting '{selected_key}' is now {state_text}.")

    # -------------------------------------------------------------
    # 8. WEEKLY SCHEDULER
    # -------------------------------------------------------------
    def run_weekly_scheduler(self) -> None:
        clear_screen()
        print_banner(self.admin_status, __version__)
        print_header("Weekly Checker & Automation")

        status = self.scheduler.get_status()
        if status:
            print_success("Weekly task is currently SCHEDULED.")
            for k, v in status.items():
                print_item(k, v)
        else:
            print_warning("No weekly check task is currently registered.")

        print(f"\n{Colors.CYAN}[1]{Colors.RESET} Enable / Update Weekly Maintenance Schedule")
        print(f"{Colors.CYAN}[2]{Colors.RESET} Remove Weekly Maintenance Schedule")
        print(f"{Colors.CYAN}[0]{Colors.RESET} Return to Menu")

        choice = prompt_choice("Select an action", ["1", "2", "0"])
        if choice == "1":
            day = input("Enter day of week (e.g. SUN, MON, SAT) [default: SUN]: ").strip().upper() or "SUN"
            time_str = input("Enter time in 24h format (e.g. 10:00, 18:30) [default: 10:00]: ").strip() or "10:00"
            ok, msg = self.scheduler.schedule_weekly(day, time_str)
            if ok: print_success(msg)
            else: print_error(msg)
        elif choice == "2":
            ok, msg = self.scheduler.remove_schedule()
            if ok: print_success(msg)
            else: print_error(msg)

    # -------------------------------------------------------------
    # 9. RESTORE REGISTRY BACKUP
    # -------------------------------------------------------------
    def run_restore_backup(self) -> None:
        print_header("Restore Registry Backup")
        info = self.backup_mgr.get_existing_backup_info()

        if not info:
            print_warning("No registry backup found in backups/ directory.")
            return

        print_info("Active Single Registry Backup:")
        print_item("File", str(info["path"]))
        print_item("Date Created", str(info["modified_str"]))
        print_item("File Size", format_bytes(int(info["size_bytes"])))

        print(f"\n{Colors.YELLOW}Restoring this backup will re-import the keys/values that were cleaned.{Colors.RESET}")
        if prompt_yes_no("Do you want to restore this registry backup now?", default=False):
            print_info("Importing backup into Windows Registry...")
            ok, msg = self.backup_mgr.restore_latest_backup()
            if ok: print_success(msg)
            else: print_error(msg)
        else:
            print_info("Restore cancelled.")

    # -------------------------------------------------------------
    # 7. WINDOWS SERVICES AUDIT
    # -------------------------------------------------------------
    def run_services_audit(self, scan_only: bool = False) -> None:
        print_header("Windows Services Audit")
        print_info("Scanning registered Windows services in registry for orphaned or broken entries...")

        report = self.services_auditor.scan(progress_callback=print_info)

        print(f"\n{Colors.BOLD}--- SERVICES AUDIT SUMMARY ---{Colors.RESET}")
        print_item("Total Services Scanned", f"{report.total_scanned:,}")
        print_item("Healthy / Active Services", f"{report.healthy_services_count:,}")
        print_item("Disabled Services", f"{len(report.disabled_services):,}")
        orphan_color = Colors.BRIGHT_RED if report.orphaned_services else Colors.BRIGHT_GREEN
        print_item("Orphaned Services (Missing Binary)", f"{orphan_color}{len(report.orphaned_services)}{Colors.RESET}")

        if not report.orphaned_services:
            print_success("\nNo orphaned services found! All service image paths point to valid executables on disk.")
            if report.disabled_services and sys.stdin.isatty() and prompt_yes_no("\nView list of disabled services?", default=False):
                headers = ["#", "Service Name", "Display Name", "Path"]
                rows = [
                    [str(i + 1), s.name[:20], s.display_name[:25], s.resolved_path[:40]]
                    for i, s in enumerate(report.disabled_services[:15])
                ]
                print_table(headers, rows)
            return

        headers = ["#", "Service Name", "Display Name", "Startup", "Missing Path"]
        rows = [
            [str(i + 1), s.name[:18], s.display_name[:20], s.start_type_str, s.resolved_path[:35]]
            for i, s in enumerate(report.orphaned_services)
        ]
        print(f"\n{Colors.BOLD}Orphaned Services Found (Executable deleted / uninstalled):{Colors.RESET}")
        print_table(headers, rows)

        if scan_only or not sys.stdin.isatty():
            print_success("Scan completed. No services were modified.")
            return

        print(f"\n{Colors.CYAN}[1]{Colors.RESET} Clean All Orphaned Services (Deletes service with single registry backup)")
        print(f"{Colors.CYAN}[2]{Colors.RESET} Inspect / Delete Individual Service")
        print(f"{Colors.CYAN}[3]{Colors.RESET} Disable All Orphaned Services (Safe)")
        print(f"{Colors.CYAN}[0]{Colors.RESET} Return to Main Menu")

        choice = prompt_choice("Select an action", ["1", "2", "3", "0"])

        if choice == "1":
            if not self.check_and_warn_apps():
                return
            if prompt_yes_no(f"Are you sure you want to delete all {len(report.orphaned_services)} orphaned service(s)?", default=True):
                for s in report.orphaned_services:
                    ok, msg = self.services_auditor.delete_orphaned_service(s, progress_callback=print_info)
                    if ok: print_success(msg)
                    else: print_error(msg)
        elif choice == "2":
            idx_str = input(f"Enter service number (1-{len(report.orphaned_services)}): ").strip()
            if idx_str.isdigit() and 1 <= int(idx_str) <= len(report.orphaned_services):
                svc = report.orphaned_services[int(idx_str) - 1]
                print(f"\n{Colors.BOLD}Service Details:{Colors.RESET}")
                print_item("Name", svc.name)
                print_item("Display Name", svc.display_name)
                print_item("Missing Executable", svc.resolved_path)
                print_item("Startup Type", svc.start_type_str)
                print(f"\n{Colors.CYAN}[D]{Colors.RESET} Delete Service (with single registry backup)")
                print(f"{Colors.CYAN}[S]{Colors.RESET} Disable Service")
                print(f"{Colors.CYAN}[0]{Colors.RESET} Cancel")
                act = prompt_choice("Select action", ["D", "d", "S", "s", "0"]).upper()
                if act == "D":
                    if not self.check_and_warn_apps():
                        return
                    ok, msg = self.services_auditor.delete_orphaned_service(svc, progress_callback=print_info)
                    if ok: print_success(msg)
                    else: print_error(msg)
                elif act == "S":
                    ok, msg = self.services_auditor.disable_service(svc, progress_callback=print_info)
                    if ok: print_success(msg)
                    else: print_error(msg)
        elif choice == "3":
            for s in report.orphaned_services:
                ok, msg = self.services_auditor.disable_service(s, progress_callback=print_info)
                if ok: print_success(msg)
                else: print_error(msg)

    # -------------------------------------------------------------
    # 8. ENVIRONMENT VARIABLE PATH CLEANUP
    # -------------------------------------------------------------
    def run_env_cleanup(self, skip_confirm: bool = False, scan_only: bool = False) -> None:
        print_header("Environment Variable PATH Cleanup")
        print_info("Scanning User and System PATH for non-existent folders and duplicate entries...")

        report = self.env_cleaner.scan(progress_callback=print_info)

        print_item("User PATH Total Entries", str(report.user_total))
        print_item("System PATH Total Entries", str(report.system_total))
        print_item("Stale Directories Found", str(report.stale_count))
        print_item("Duplicate Entries Found", str(report.duplicate_count))

        if not report.stale_entries and not report.duplicate_entries:
            print_success("\nEnvironment PATH is completely clean! No stale or duplicate directories found.")
            return

        if report.stale_entries:
            print(f"\n{Colors.BOLD}Stale Directories in PATH (Directories do not exist on disk):{Colors.RESET}")
            headers = ["Scope", "Path Entry", "Reason"]
            rows = [[e.scope, e.original[:60], e.reason] for e in report.stale_entries]
            print_table(headers, rows)

        if report.duplicate_entries:
            print(f"\n{Colors.BOLD}Duplicate Entries in PATH:{Colors.RESET}")
            headers = ["Scope", "Duplicate Path"]
            rows = [[e.scope, e.original[:60]] for e in report.duplicate_entries]
            print_table(headers, rows)

        if scan_only:
            print_success("Scan completed (Dry-run mode). Environment variables were not modified.")
            return

        if not self.check_and_warn_apps(skip_confirm=skip_confirm):
            return

        if not skip_confirm:
            if not prompt_yes_no("\nProceed with cleaning stale and duplicate PATH entries?", default=True):
                print_warning("Environment PATH cleanup cancelled.")
                return

        print_info("Cleaning PATH and updating Windows Registry...")
        clean_rep = self.env_cleaner.clean(
            report,
            clean_user=True,
            clean_system=self.admin_status,
            remove_stale=True,
            remove_duplicates=True,
            progress_callback=print_info,
        )

        if clean_rep.backup_file:
            print_success(f"Single registry backup updated: {clean_rep.backup_file.name}")
        print_success(f"Cleaned {clean_rep.cleaned_stale} stale entries and {clean_rep.cleaned_duplicates} duplicates!")
        if clean_rep.broadcast_success:
            print_success("Environment change broadcast successfully to running applications.")

    # -------------------------------------------------------------
    # 9. WINDOWS EVENT LOG SUMMARY
    # -------------------------------------------------------------
    def run_event_log_summary(self, hours: Optional[int] = None, include_warnings: bool = False) -> None:
        print_header("Windows Event Log Summary & Diagnostics")
        print_info("Spotting system warnings, hardware issues, driver faults, and application crashes...")

        if not self.event_log_viewer.is_available():
            print_error("wevtutil.exe was not found on this system.")
            return

        if hours is None and sys.stdin.isatty():
            print(f"\n{Colors.BOLD}Select Inspection Timeframe:{Colors.RESET}")
            print(f"  {Colors.CYAN}[1]{Colors.RESET} Last 24 Hours (Errors & Critical events)")
            print(f"  {Colors.CYAN}[2]{Colors.RESET} Last 7 Days (Errors & Critical events)")
            print(f"  {Colors.CYAN}[3]{Colors.RESET} Last 24 Hours (Include Warnings)")
            print(f"  {Colors.CYAN}[0]{Colors.RESET} Return to Menu")

            choice = prompt_choice("Choose timeframe", ["1", "2", "3", "0"])
            if choice == "0":
                return

            hours = 24 if choice in ("1", "3") else 168
            include_warnings = (choice == "3")
        elif hours is None:
            hours = 24

        summary = self.event_log_viewer.get_recent_events(
            hours=hours,
            include_warnings=include_warnings,
            progress_callback=print_info,
        )

        print(f"\n{Colors.BOLD}--- EVENT LOG HEALTH REPORT (Last {hours}h) ---{Colors.RESET}")
        print_item("Critical Events", f"{Colors.BRIGHT_RED}{summary.total_critical}{Colors.RESET}")
        print_item("Error Events", f"{Colors.BRIGHT_YELLOW}{summary.total_error}{Colors.RESET}")
        if include_warnings:
            print_item("Warning Events", f"{Colors.CYAN}{summary.total_warning}{Colors.RESET}")
        print_item("Total Logged Events", str(len(summary.events)))

        if not summary.events:
            print_success("\nNo critical errors or crashes logged in this timeframe! System is running smoothly.")
            return

        if summary.top_sources:
            print(f"\n{Colors.BOLD}Top Event Sources:{Colors.RESET}")
            for src, cnt in summary.top_sources:
                print(f"  • {Colors.BOLD}{src}{Colors.RESET}: {cnt} occurrence(s)")

        if summary.recurring_issues:
            print(f"\n{Colors.BOLD}Recurring Issues / Faults (Occurred 2+ times):{Colors.RESET}")
            headers = ["Count", "Source", "Event ID", "Sample Diagnosis"]
            rows = [
                [str(r["count"]), r["source"][:25], str(r["event_id"]), r["sample_desc"][:45]]
                for r in summary.recurring_issues[:10]
            ]
            print_table(headers, rows)

        print(f"\n{Colors.BOLD}Recent Event Stream (Top 10 Newest):{Colors.RESET}")
        for i, ev in enumerate(summary.events[:10]):
            lvl_color = Colors.BRIGHT_RED if ev.level == "Critical" else (Colors.BRIGHT_YELLOW if ev.level == "Error" else Colors.CYAN)
            print(f"\n  [{i + 1}] {lvl_color}[{ev.level}]{Colors.RESET} {Colors.GRAY}{ev.date_str}{Colors.RESET} | {Colors.BOLD}{ev.log_name}:{ev.source}{Colors.RESET} (ID: {ev.event_id})")
            print(f"      {ev.description[:130]}")
            if len(ev.description) > 130:
                print(f"      {Colors.GRAY}...{Colors.RESET}")

    # -------------------------------------------------------------
    # MANUAL MODE DASHBOARD
    # -------------------------------------------------------------
    def run_manual_menu(self) -> None:
        while True:
            clear_screen()
            print_banner(self.admin_status, __version__)

            print(f"""  {Colors.BOLD}Manual Dashboard:{Colors.RESET}
  {Colors.BRIGHT_GREEN}[1]  🚀 All-in-One Care{Colors.RESET}          (Full scan, junk, registry, PATH clean & app updates)
  {Colors.BRIGHT_CYAN}[2]  🔄 Update Apps{Colors.RESET}              (Scan & upgrade software via Winget)
  {Colors.BRIGHT_YELLOW}[3]  🧹 Junk Cleanup{Colors.RESET}             (Deep clean temp, history, caches, leftovers)
  {Colors.BRIGHT_MAGENTA}[4]  🛡️  Registry Cleanup{Colors.RESET}         (Scan broken keys, single backup & fix)
  {Colors.WHITE}[5]  👥 Multi-Version Apps{Colors.RESET}        (Detect & remove duplicate co-existing versions)
  {Colors.WHITE}[6]  🤖 Smart Process Guardian{Colors.RESET}    (AI-style process & resource diagnosis)
  {Colors.WHITE}[7]  🧹 Windows Services Audit{Colors.RESET}    (Detect orphaned & uninstalled services)
  {Colors.WHITE}[8]  🔧 Environment PATH Cleanup{Colors.RESET}  (Clean stale directories & duplicate PATHs)
  {Colors.WHITE}[9]  📋 Event Log Summary{Colors.RESET}         (Spot recent system errors & app crashes)
  {Colors.WHITE}[10] ⚙️  Customization & Settings{Colors.RESET} (Configure cleanup toggles & exclusions)
  {Colors.WHITE}[11] 📅 Weekly Scheduler{Colors.RESET}         (Automate regular weekly maintenance)
  {Colors.WHITE}[12] ⏪ Restore Registry{Colors.RESET}         (Undo latest registry cleanup)
  {Colors.GRAY}[0]  ⬅️  Back to Startup Mode{Colors.RESET}
  {Colors.GRAY}{'─' * 60}{Colors.RESET}""")

            choice = prompt_choice("Select an option", ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "0"])

            if choice == "1":
                self.run_all_in_one()
                pause()
            elif choice == "2":
                self.run_update_apps()
                pause()
            elif choice == "3":
                self.run_junk_cleanup()
                pause()
            elif choice == "4":
                self.run_registry_cleanup()
                pause()
            elif choice == "5":
                self.run_multi_version_manager()
                pause()
            elif choice == "6":
                self.run_process_guardian()
                pause()
            elif choice == "7":
                self.run_services_audit()
                pause()
            elif choice == "8":
                self.run_env_cleanup()
                pause()
            elif choice == "9":
                self.run_event_log_summary()
                pause()
            elif choice == "10":
                self.run_settings()
            elif choice == "11":
                self.run_weekly_scheduler()
                pause()
            elif choice == "12":
                self.run_restore_backup()
                pause()
            elif choice == "0":
                break

    # -------------------------------------------------------------
    # PRIMARY STARTUP MODE SELECTOR
    # -------------------------------------------------------------
    def run_mode_selector(self) -> None:
        while True:
            clear_screen()
            print_banner(self.admin_status, __version__)

            print(f"""  {Colors.BOLD}Choose Maintenance Mode:{Colors.RESET}

  {Colors.BRIGHT_GREEN}[1] 🚀 Auto Mode{Colors.RESET}   — One-Click Smart System Care
      {Colors.GRAY}Automated junk clean, single-backup registry repair,
      PATH cleanup, duplicate multi-version app purge, Process Guardian & updates.{Colors.RESET}

  {Colors.BRIGHT_CYAN}[2] 🛠️  Manual Mode{Colors.RESET} — Interactive Dashboard
      {Colors.GRAY}Individual tools: services audit, environment PATH cleanup,
      event log summary, process guardian, scheduler & settings.{Colors.RESET}

  {Colors.GRAY}[0] ❌ Exit{Colors.RESET}
  {Colors.GRAY}{'─' * 60}{Colors.RESET}""")

            choice = prompt_choice("Select mode", ["1", "2", "0"])
            if choice == "1":
                self.run_auto_mode()
                pause()
            elif choice == "2":
                self.run_manual_menu()
            elif choice == "0":
                print(f"\n{Colors.BRIGHT_GREEN}Thank you for using SysCare! Have a great day.{Colors.RESET}\n")
                break


def main():
    parser = argparse.ArgumentParser(description="SysCare - Personal Windows Care, Cleaner & Optimizer")
    parser.add_argument("--auto", action="store_true", help="Run Auto Mode (one-click automated care)")
    parser.add_argument("--all", action="store_true", help="Run All-in-One maintenance")
    parser.add_argument("--junk", action="store_true", help="Run Junk & Privacy cleanup")
    parser.add_argument("--registry", action="store_true", help="Run Registry cleanup")
    parser.add_argument("--update", action="store_true", help="Check and update apps via winget")
    parser.add_argument("--multiver", action="store_true", help="Scan and clean duplicate multi-version apps")
    parser.add_argument("--guardian", action="store_true", help="Run Smart Process Guardian")
    parser.add_argument("--services", action="store_true", help="Run Windows Services audit")
    parser.add_argument("--env", action="store_true", help="Scan and clean Environment variable PATH")
    parser.add_argument("--events", action="store_true", help="Show recent Windows Event Log error summary")
    parser.add_argument("--scan", action="store_true", help="Dry-run scan only, do not delete anything")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompts (one-click automated)")
    parser.add_argument("--manual", action="store_true", help="Launch directly into Manual Mode dashboard")

    args = parser.parse_args()

    # Enforce Administrator privileges to prevent permission errors
    is_read_only = args.scan or args.guardian or args.multiver or args.events
    if not is_admin() and not is_read_only:
        print_banner(False, __version__)
        print_warning("Administrator privileges are required to prevent permission errors.")
        print_info("Requesting elevation via Windows User Account Control (UAC)...")
        if relaunch_as_admin(sys.argv[1:]):
            sys.exit(0)
        else:
            print_error("Administrator elevation was denied or failed.")
            print_info("Please right-click SysCare.bat and choose 'Run as administrator'.")
            pause()
            sys.exit(1)

    app = SysCareApp()

    # CLI flag execution
    if args.auto:
        app.run_auto_mode(skip_confirm=args.yes)
    elif args.all:
        app.run_all_in_one(skip_confirm=args.yes, scan_only=args.scan)
    elif args.junk:
        app.run_junk_cleanup(skip_confirm=args.yes, scan_only=args.scan)
    elif args.registry:
        app.run_registry_cleanup(skip_confirm=args.yes, scan_only=args.scan)
    elif args.update:
        app.run_update_apps()
    elif args.multiver:
        app.run_multi_version_manager()
    elif args.guardian:
        app.run_process_guardian()
    elif args.services:
        app.run_services_audit(scan_only=args.scan)
    elif args.env:
        app.run_env_cleanup(skip_confirm=args.yes, scan_only=args.scan)
    elif args.events:
        app.run_event_log_summary()
    elif args.manual:
        app.run_manual_menu()
    else:
        # Default: launch interactive mode selector (Auto vs Manual)
        app.run_mode_selector()


if __name__ == "__main__":
    main()

