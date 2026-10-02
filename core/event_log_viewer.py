"""
Windows Event Log Viewer & Diagnostic Summary for SysCare
Pulls recent Critical and Error events from Windows System and Application logs
using native wevtutil.exe to spot hardware, driver, and application failures early.
Zero external dependencies.
"""

import os
import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


@dataclass
class EventItem:
    log_name: str
    source: str
    date_str: str
    event_id: int
    level: str  # "Critical", "Error", "Warning"
    description: str


@dataclass
class EventLogSummary:
    events: List[EventItem] = field(default_factory=list)
    timeframe_hours: int = 24
    total_critical: int = 0
    total_error: int = 0
    total_warning: int = 0
    top_sources: List[Tuple[str, int]] = field(default_factory=list)
    recurring_issues: List[Dict] = field(default_factory=list)


class EventLogViewer:
    """Queries and parses recent Windows Event Log events for diagnostic health check."""

    def __init__(self):
        pass

    def is_available(self) -> bool:
        """Checks if wevtutil.exe is available in Windows system directory."""
        windir = os.environ.get("WINDIR", "C:\\Windows")
        wevtutil_path = Path(windir) / "System32" / "wevtutil.exe"
        return wevtutil_path.exists()

    def get_recent_events(
        self,
        hours: int = 24,
        include_warnings: bool = False,
        max_events_per_log: int = 50,
        channels: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> EventLogSummary:
        """
        Retrieves recent events from System and Application logs within the specified timeframe.
        """
        if channels is None:
            channels = ["System", "Application"]

        all_events: List[EventItem] = []
        ms = hours * 3600 * 1000

        # Build XPath query: Level 1=Critical, Level 2=Error, Level 3=Warning
        level_filter = "Level=1 or Level=2"
        if include_warnings:
            level_filter += " or Level=3"

        xpath_query = f"*[System[({level_filter}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"

        for channel in channels:
            if progress_callback:
                progress_callback(f"Querying Windows {channel} log for errors in the last {hours}h...")

            cmd = [
                "wevtutil.exe",
                "qe",
                channel,
                f"/q:{xpath_query}",
                "/f:text",
                f"/c:{max_events_per_log}",
                "/rd:true",
            ]

            try:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=15,
                    check=False,
                )
                if res.returncode == 0 and res.stdout:
                    parsed = self._parse_wevtutil_text(res.stdout, channel)
                    all_events.extend(parsed)
            except Exception as e:
                if progress_callback:
                    progress_callback(f"Error reading {channel} log: {e}")

        # Sort all events chronologically (newest first)
        all_events.sort(key=lambda x: x.date_str, reverse=True)

        summary = EventLogSummary(events=all_events, timeframe_hours=hours)
        summary.total_critical = sum(1 for e in all_events if e.level == "Critical")
        summary.total_error = sum(1 for e in all_events if e.level == "Error")
        summary.total_warning = sum(1 for e in all_events if e.level == "Warning")

        # Compute top sources
        source_counts = Counter(e.source for e in all_events)
        summary.top_sources = source_counts.most_common(5)

        # Compute recurring issues (source + event_id)
        issue_groups: Dict[Tuple[str, int], List[EventItem]] = {}
        for ev in all_events:
            key = (ev.source, ev.event_id)
            issue_groups.setdefault(key, []).append(ev)

        recurring = []
        for (src, eid), ev_list in sorted(issue_groups.items(), key=lambda x: len(x[1]), reverse=True):
            if len(ev_list) > 1:
                sample = ev_list[0]
                recurring.append({
                    "source": src,
                    "event_id": eid,
                    "count": len(ev_list),
                    "level": sample.level,
                    "log_name": sample.log_name,
                    "sample_desc": sample.description[:120],
                })
        summary.recurring_issues = recurring

        return summary

    def _parse_wevtutil_text(self, text_output: str, fallback_channel: str) -> List[EventItem]:
        """Parses the text format returned by wevtutil."""
        events: List[EventItem] = []
        raw_events = re.split(r"\nEvent\[\d+\]\s*\n", text_output)

        for raw in raw_events:
            cleaned = raw.strip()
            if not cleaned:
                continue

            event_id = 0
            log_name = fallback_channel
            source = "Unknown"
            date_str = ""
            level = "Error"
            description = ""

            # Extract fields line by line
            lines = cleaned.splitlines()
            desc_lines = []
            is_in_desc = False

            for line in lines:
                if is_in_desc:
                    desc_lines.append(line)
                    continue

                line_s = line.strip()
                if line_s.startswith("Log Name:"):
                    log_name = line_s.split(":", 1)[1].strip()
                elif line_s.startswith("Source:"):
                    source = line_s.split(":", 1)[1].strip()
                elif line_s.startswith("Date:"):
                    date_str = line_s.split(":", 1)[1].strip()
                    # Clean up ISO date to readable string
                    try:
                        # e.g. 2026-09-11T09:29:42.3620000Z
                        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                        date_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        pass
                elif line_s.startswith("Event ID:"):
                    try:
                        event_id = int(line_s.split(":", 1)[1].strip())
                    except ValueError:
                        pass
                elif line_s.startswith("Level:"):
                    level_raw = line_s.split(":", 1)[1].strip()
                    if "Critical" in level_raw:
                        level = "Critical"
                    elif "Warning" in level_raw:
                        level = "Warning"
                    else:
                        level = "Error"
                elif line_s.startswith("Description:"):
                    is_in_desc = True

            description = " ".join(" ".join(desc_lines).split()).strip()
            if not description:
                description = f"Event {event_id} from {source}"

            events.append(
                EventItem(
                    log_name=log_name,
                    source=source,
                    date_str=date_str,
                    event_id=event_id,
                    level=level,
                    description=description,
                )
            )

        return events
