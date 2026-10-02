"""
Console UI & ANSI Color Utilities for SysCare
Zero external dependencies; uses Windows 10/11 native Virtual Terminal Processing.
"""

import ctypes
import os
import sys
from typing import List, Optional

# Enable Virtual Terminal Processing on Windows console & UTF-8 output
def init_terminal() -> bool:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        if handle == -1 or handle == 0:
            return False
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            new_mode = mode.value | 0x0004
            kernel32.SetConsoleMode(handle, new_mode)
            return True
    except Exception:
        pass
    return False

# Initialize on import
_VT_SUPPORTED = init_terminal()

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    BG_BLUE = "\033[44m"
    BG_DARK = "\033[40m"


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def format_bytes(size_bytes: int) -> str:
    """Converts raw byte count into human-readable string (KB, MB, GB)."""
    if size_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)
    while size >= 1024.0 and i < len(units) - 1:
        size /= 1024.0
        i += 1
    return f"{size:.2f} {units[i]}" if i > 0 else f"{int(size)} B"


def print_banner(is_admin: bool = False, version: str = "1.0.0") -> None:
    admin_badge = (
        f"{Colors.BG_BLUE}{Colors.BRIGHT_WHITE} [ADMINISTRATOR] {Colors.RESET}"
        if is_admin
        else f"{Colors.YELLOW}[STANDARD USER - User-level cleanup]{Colors.RESET}"
    )
    
    banner = f"""{Colors.BRIGHT_CYAN}
  ███████╗██╗   ██╗███████╗ ██████╗ █████╗ ██████╗ ███████╗
  ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝
  ███████╗ ╚████╔╝ ███████╗██║     ███████║██████╔╝█████╗  
  ╚════██║  ╚██╔╝  ╚════██║██║     ██╔══██║██╔══██╗██╔══╝  
  ███████║   ██║   ███████║╚██████╗██║  ██║██║  ██║███████╗
  ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝{Colors.RESET}
  {Colors.BOLD}Personal Windows Care, Cleaner & Optimizer{Colors.RESET} v{version}
  Status: {admin_badge}
  {Colors.GRAY}{'─' * 60}{Colors.RESET}"""
    print(banner)


def print_header(title: str) -> None:
    print(f"\n{Colors.BRIGHT_CYAN}{Colors.BOLD}=== {title.upper()} ==={Colors.RESET}")
    print(f"{Colors.GRAY}{'─' * (len(title) + 8)}{Colors.RESET}")


def print_info(msg: str) -> None:
    print(f"{Colors.BRIGHT_BLUE}ℹ{Colors.RESET} {msg}")


def print_success(msg: str) -> None:
    print(f"{Colors.BRIGHT_GREEN}✔{Colors.RESET} {msg}")


def print_warning(msg: str) -> None:
    print(f"{Colors.BRIGHT_YELLOW}▲{Colors.RESET} {msg}")


def print_error(msg: str) -> None:
    print(f"{Colors.BRIGHT_RED}✖{Colors.RESET} {msg}")


def print_step(step: int, total: int, msg: str) -> None:
    print(f"{Colors.CYAN}[{step}/{total}]{Colors.RESET} {msg}")


def print_item(label: str, value: str, indent: int = 2) -> None:
    spaces = " " * indent
    print(f"{spaces}{Colors.GRAY}•{Colors.RESET} {Colors.BOLD}{label}:{Colors.RESET} {value}")


def print_close_apps_warning(detected_apps: Optional[List[str]] = None) -> None:
    """Displays a prominent warning to close third-party applications before cleaning."""
    print(f"\n{Colors.BRIGHT_YELLOW}{'═' * 66}{Colors.RESET}")
    print(f" {Colors.BOLD}{Colors.BRIGHT_YELLOW}⚠️  IMPORTANT: PLEASE CLOSE ALL THIRD-PARTY APPLICATIONS{Colors.RESET}")
    print(f" {Colors.YELLOW}To prevent locked files, corrupted browser caches, or lost work,{Colors.RESET}")
    print(f" {Colors.YELLOW}please save your work and close all open applications (browsers,{Colors.RESET}")
    print(f" {Colors.YELLOW}code editors, office apps, chat clients, and games).{Colors.RESET}")
    if detected_apps:
        apps_str = ", ".join(detected_apps)
        print(f"\n {Colors.BRIGHT_RED}📌 Detected currently running:{Colors.RESET} {Colors.BOLD}{apps_str}{Colors.RESET}")
    print(f"{Colors.BRIGHT_YELLOW}{'═' * 66}{Colors.RESET}\n")


def print_table(headers: List[str], rows: List[List[str]]) -> None:
    """Renders a clean ASCII table."""
    if not rows:
        print(f"  {Colors.GRAY}(no items found){Colors.RESET}")
        return

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(val)))

    # Header
    hdr_line = "  ".join(f"{h:<{col_widths[i]}}" for i, h in enumerate(headers))
    print(f"{Colors.BOLD}{Colors.BRIGHT_WHITE}{hdr_line}{Colors.RESET}")
    print(f"{Colors.GRAY}{'─' * sum(col_widths) + '─' * (2 * (len(headers) - 1))}{Colors.RESET}")

    # Rows
    for row in rows:
        row_line = "  ".join(f"{str(v):<{col_widths[i]}}" for i, v in enumerate(row))
        print(row_line)


def prompt_yes_no(question: str, default: bool = True) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    sys.stdout.write(f"{Colors.BRIGHT_YELLOW}?{Colors.RESET} {question} {Colors.GRAY}{hint}{Colors.RESET} ")
    sys.stdout.flush()
    try:
        resp = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False

    if not resp:
        return default
    return resp in ("y", "yes", "1", "true")


def prompt_choice(prompt_text: str, options: List[str]) -> str:
    valid = set(opt.lower() for opt in options)
    while True:
        sys.stdout.write(f"{Colors.BRIGHT_CYAN}> {prompt_text}:{Colors.RESET} ")
        sys.stdout.flush()
        try:
            choice = input().strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return options[-1]
        if choice.lower() in valid:
            return choice
        print(f"  {Colors.RED}Invalid selection. Options: {', '.join(options)}{Colors.RESET}")


def pause(message: str = "Press Enter to return to menu...") -> None:
    if not sys.stdin.isatty():
        return
    print(f"\n{Colors.GRAY}{message}{Colors.RESET}")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass
