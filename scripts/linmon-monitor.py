#!/usr/bin/env python3
"""
LinMon Real-Time Monitoring Dashboard

A top/htop-like terminal dashboard for monitoring LinMon activity in real-time.
Displays live event streaming, aggregate statistics, and performance monitoring.

Uses curses (built-in) and rich (system package) for terminal UI.
"""

import curses
import json
import sys
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from io import StringIO

from rich.console import Console
from rich.table import Table as RichTable
from rich.text import Text


# Event type constants (from bpf/common.h)
EVENT_TYPES = {
    1: "EXEC",
    2: "EXIT",
    3: "FILE_OPEN",
    4: "FILE_CREATE",
    5: "FILE_DELETE",
    6: "FILE_MODIFY",
    7: "TCP_CONN",
    8: "TCP_ACCEPT",
    9: "SETUID",
    10: "SETGID",
    11: "SUDO",
    12: "UDP_SEND",
    13: "UDP_RECV",
    14: "PTRACE",
    15: "MODULE",
    16: "MEMFD",
    17: "BIND",
    18: "UNSHARE",
    19: "EXECVEAT",
    20: "BPF",
    21: "CRED_READ",
    22: "LDPRELOAD",
    23: "VSOCK",
    24: "PERSISTENCE",
    25: "SUID",
    26: "CRED_WRITE",
    27: "LOG_TAMPER",
    28: "RAW_DISK",
}

# Event categories for filtering
EVENT_CATEGORIES = {
    "process": {1, 2},  # EXEC, EXIT
    "network": {7, 8, 12, 13, 23},  # TCP, UDP, VSOCK
    "security": {14, 15, 16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 27, 28},
    "file": {3, 4, 5, 6},
    "privilege": {9, 10, 11},
}


class LogReader:
    """Reads LinMon log file with initial history and live tailing."""

    def __init__(self, log_path: Path, history_lines: int = 1000):
        self.log_path = log_path
        self.history_lines = history_lines
        self.file = None
        self.inode = None
        self.malformed_count = 0

    def read_history(self) -> List[Dict]:
        """Read last N lines from log file."""
        import subprocess

        if not self.log_path.exists():
            return []

        try:
            result = subprocess.run(
                ["tail", f"-n{self.history_lines}", str(self.log_path)],
                capture_output=True,
                text=True,
                check=True
            )
            events = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    event = self._parse_line(line)
                    if event:
                        events.append(event)
            return events
        except Exception:
            return []

    def open_file(self) -> bool:
        """Open log file for tailing."""
        try:
            if not self.log_path.exists():
                return False

            self.file = open(self.log_path, 'r')
            self.file.seek(0, 2)  # Seek to end
            self.inode = self.log_path.stat().st_ino
            return True
        except Exception:
            return False

    def check_rotation(self) -> bool:
        """Check if log file was rotated."""
        try:
            current_inode = self.log_path.stat().st_ino
            return current_inode != self.inode
        except Exception:
            return False

    def read_new_events(self) -> List[Dict]:
        """Read new events from file."""
        if not self.file:
            return []

        # Check for rotation
        if self.check_rotation():
            self.file.close()
            if self.open_file():
                return []  # Will read new events on next call

        events = []
        try:
            for line in self.file:
                line = line.strip()
                if line:
                    event = self._parse_line(line)
                    if event:
                        events.append(event)
        except Exception:
            pass

        return events

    def _parse_line(self, line: str) -> Optional[Dict]:
        """Parse JSON line into event dict."""
        try:
            event = json.loads(line)
            # Add parsed timestamp for display
            if 'timestamp' in event:
                dt = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                event['_time'] = dt.strftime('%H:%M:%S')
            return event
        except json.JSONDecodeError:
            self.malformed_count += 1
            return None
        except Exception:
            self.malformed_count += 1
            return None


class StatsCollector:
    """Collects and maintains rolling statistics."""

    def __init__(self):
        self.event_count = 0
        self.type_counts = defaultdict(int)
        self.process_counts = defaultdict(int)
        self.user_counts = defaultdict(int)

        # Event rate tracking
        self.event_times = deque(maxlen=1000)

    def add_event(self, event: Dict):
        """Add event to statistics."""
        self.event_count += 1
        self.event_times.append(time.time())

        # Count by type
        event_type = event.get('type')
        if event_type:
            self.type_counts[event_type] += 1

        # Count by process
        process_name = event.get('process_name', event.get('comm', 'unknown'))
        self.process_counts[process_name] += 1

        # Count by user
        username = event.get('username', f"uid_{event.get('uid', '?')}")
        self.user_counts[username] += 1

    def get_event_rate(self, seconds: int) -> float:
        """Get events per second over last N seconds."""
        if not self.event_times:
            return 0.0

        now = time.time()
        cutoff = now - seconds
        recent = [t for t in self.event_times if t >= cutoff]

        if len(recent) < 2:
            return 0.0

        return len(recent) / seconds

    def get_type_breakdown(self) -> Dict[str, int]:
        """Get event counts by category."""
        breakdown = defaultdict(int)
        for event_type, count in self.type_counts.items():
            for category, types in EVENT_CATEGORIES.items():
                if event_type in types:
                    breakdown[category] += count
                    break
        return breakdown

    def get_top_processes(self, n: int = 3) -> List[tuple]:
        """Get top N processes by event count."""
        return sorted(self.process_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_top_users(self, n: int = 3) -> List[tuple]:
        """Get top N users by event count."""
        return sorted(self.user_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def reset(self):
        """Reset all counters."""
        self.event_count = 0
        self.type_counts.clear()
        self.process_counts.clear()
        self.user_counts.clear()
        self.event_times.clear()


class EventFilter:
    """Filters events based on user criteria."""

    def __init__(self):
        self.event_types: Optional[Set[int]] = None
        self.username_filter: str = ""

    def set_category_filter(self, category: str):
        """Set filter to specific event category."""
        if category in EVENT_CATEGORIES:
            self.event_types = EVENT_CATEGORIES[category]
        else:
            self.event_types = None

    def clear_type_filter(self):
        """Clear event type filter."""
        self.event_types = None

    def set_username_filter(self, username: str):
        """Set username filter."""
        self.username_filter = username.lower()

    def clear_username_filter(self):
        """Clear username filter."""
        self.username_filter = ""

    def clear_all(self):
        """Clear all filters."""
        self.event_types = None
        self.username_filter = ""

    def matches(self, event: Dict) -> bool:
        """Check if event matches current filters."""
        # Type filter
        if self.event_types is not None:
            event_type = event.get('type')
            if event_type not in self.event_types:
                return False

        # Username filter
        if self.username_filter:
            username = event.get('username', '').lower()
            if self.username_filter not in username:
                return False

        return True

    def get_active_filters(self) -> List[str]:
        """Get list of active filter descriptions."""
        filters = []
        if self.event_types is not None:
            for category, types in EVENT_CATEGORIES.items():
                if types == self.event_types:
                    filters.append(f"{category.title()} Events")
                    break
        if self.username_filter:
            filters.append(f"User: {self.username_filter}")
        return filters


class Dashboard:
    """Main dashboard with curses UI."""

    def __init__(self, stdscr, log_path: Path):
        self.stdscr = stdscr
        self.log_path = log_path
        self.reader = LogReader(log_path)
        self.stats = StatsCollector()
        self.event_filter = EventFilter()
        self.events = deque(maxlen=500)
        self.paused = False
        self.scroll_offset = 0
        self.running = True

        # Color pairs
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)   # Normal
        curses.init_pair(2, curses.COLOR_CYAN, curses.COLOR_BLACK)    # Network
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)     # Security
        curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Privilege
        curses.init_pair(5, curses.COLOR_BLUE, curses.COLOR_BLACK)    # Process
        curses.init_pair(6, curses.COLOR_MAGENTA, curses.COLOR_BLACK) # Headers

        # Configure curses
        curses.curs_set(0)  # Hide cursor
        self.stdscr.nodelay(1)  # Non-blocking input
        self.stdscr.timeout(100)  # 100ms timeout

    def initialize(self):
        """Load history and open log file."""
        history = self.reader.read_history()
        for event in history:
            self.stats.add_event(event)
            if self.event_filter.matches(event):
                self.events.append(event)

        self.reader.open_file()

    def render_stats(self, win, height: int, width: int):
        """Render statistics panel."""
        win.clear()
        win.box()

        # Event rate
        rate_1s = self.stats.get_event_rate(1)
        rate_5s = self.stats.get_event_rate(5)
        rate_60s = self.stats.get_event_rate(60)

        # Color based on rate
        if rate_1s < 50:
            rate_color = curses.color_pair(1)  # Green
        elif rate_1s < 100:
            rate_color = curses.color_pair(4)  # Yellow
        else:
            rate_color = curses.color_pair(3)  # Red

        try:
            win.addstr(1, 2, f"Events/sec: ", curses.color_pair(6) | curses.A_BOLD)
            win.addstr(f"{rate_1s:.1f}", rate_color)
            win.addstr(f" (1s) | {rate_5s:.1f} (5s) | {rate_60s:.1f} (60s)")
        except curses.error:
            pass

        # Type breakdown
        breakdown = self.stats.get_type_breakdown()
        total = sum(breakdown.values()) or 1

        try:
            y = 2
            for category, color in [
                ("process", 5), ("network", 2), ("security", 3),
                ("file", 1), ("privilege", 4)
            ]:
                count = breakdown.get(category, 0)
                pct = (count / total) * 100
                blocks = int(pct / 10)
                bar = "█" * blocks + "░" * (10 - blocks)

                win.addstr(y, 2, f"{category.title():9s}: ", curses.color_pair(6))
                win.addstr(bar, curses.color_pair(color))
                win.addstr(f" {pct:3.0f}%")
                y += 1
        except curses.error:
            pass

        # Top processes and users
        top_procs = self.stats.get_top_processes(3)
        top_users = self.stats.get_top_users(2)

        try:
            win.addstr(height - 2, 2, "Top: ", curses.color_pair(6) | curses.A_BOLD)
            procs_str = " ".join(f"{name[:8]}({count})" for name, count in top_procs)
            users_str = " ".join(f"{name[:8]}({count})" for name, count in top_users)
            win.addstr(f"{procs_str}  |  Users: {users_str}"[:width-10])
        except curses.error:
            pass

        win.refresh()

    def render_events(self, win, height: int, width: int):
        """Render event stream panel."""
        win.clear()
        win.box()

        # Header
        try:
            win.addstr(0, 2, " Event Stream ", curses.color_pair(6) | curses.A_BOLD)
            win.addstr(1, 2, f"{'Time':<8} {'Type':<12} {'User':<12} {'Process':<12} Details"[:width-4],
                      curses.color_pair(6))
        except curses.error:
            pass

        # Events (show last events that fit in window)
        max_events = height - 3
        events_to_show = list(self.events)[-max_events:]

        y = 2
        for event in events_to_show:
            if y >= height - 1:
                break

            event_type = event.get('type', 0)
            type_name = EVENT_TYPES.get(event_type, f"TYPE_{event_type}")

            # Color by category
            if event_type in EVENT_CATEGORIES['security']:
                color = curses.color_pair(3) | curses.A_BOLD  # Red bold
            elif event_type in EVENT_CATEGORIES['network']:
                color = curses.color_pair(2)  # Cyan
            elif event_type in EVENT_CATEGORIES['process']:
                color = curses.color_pair(5)  # Blue
            elif event_type in EVENT_CATEGORIES['privilege']:
                color = curses.color_pair(4)  # Yellow
            else:
                color = curses.color_pair(1)  # Green

            username = event.get('username', f"uid_{event.get('uid', '?')}")[:12]
            process_name = event.get('process_name', event.get('comm', '?'))[:12]

            # Build details string
            details_parts = []
            if 'filename' in event:
                details_parts.append(event['filename'][:30])
            if 'cmdline' in event:
                details_parts.append(event['cmdline'][:40])
            if 'dest_ip' in event:
                dest_port = event.get('dest_port', '?')
                details_parts.append(f"{event['dest_ip']}:{dest_port}")
            if 'target_pid' in event:
                details_parts.append(f"target_pid={event['target_pid']}")

            details = " | ".join(details_parts) if details_parts else ""

            try:
                time_str = event.get('_time', '')[:8]
                win.addstr(y, 2, f"{time_str:<8}")
                win.addstr(y, 11, f"{type_name:<12}", color)
                win.addstr(y, 24, f"{username:<12}")
                win.addstr(y, 37, f"{process_name:<12}")
                win.addstr(y, 50, details[:width-52])
            except curses.error:
                pass

            y += 1

        # Show pause indicator
        if self.paused:
            try:
                win.addstr(0, width - 10, " PAUSED ", curses.color_pair(3) | curses.A_BOLD)
            except curses.error:
                pass

        win.refresh()

    def render_status(self, win, height: int, width: int):
        """Render status bar."""
        win.clear()
        win.box()

        # Filters
        active_filters = self.event_filter.get_active_filters()
        if active_filters:
            filter_str = "Filters: [" + "] [".join(active_filters) + "]"
        else:
            filter_str = "No filters active"

        try:
            win.addstr(1, 2, filter_str[:width-4], curses.color_pair(4))
        except curses.error:
            pass

        # Help text
        try:
            help_text = "q:Quit Space:Pause p:Proc n:Net s:Sec f:File v:Priv r:Reset Esc:Clear"
            win.addstr(2, 2, help_text[:width-4], curses.A_DIM)
        except curses.error:
            pass

        # Status
        try:
            if not self.log_path.exists():
                win.addstr(3, 2, f"⚠ Log file not found: {self.log_path}"[:width-4],
                          curses.color_pair(3))
            else:
                win.addstr(3, 2, "LinMon: Running", curses.color_pair(1))
                win.addstr(f" | Log: {self.log_path}"[:width-20])

                if self.reader.malformed_count > 0:
                    win.addstr(f" | ⚠ {self.reader.malformed_count} malformed"[:20],
                              curses.color_pair(4))
        except curses.error:
            pass

        win.refresh()

    def handle_input(self, key: int):
        """Handle keyboard input."""
        if key == ord('q'):
            self.running = False
        elif key == ord(' '):
            self.paused = not self.paused
        elif key == ord('p'):
            if self.event_filter.event_types == EVENT_CATEGORIES['process']:
                self.event_filter.clear_type_filter()
            else:
                self.event_filter.set_category_filter('process')
        elif key == ord('n'):
            if self.event_filter.event_types == EVENT_CATEGORIES['network']:
                self.event_filter.clear_type_filter()
            else:
                self.event_filter.set_category_filter('network')
        elif key == ord('s'):
            if self.event_filter.event_types == EVENT_CATEGORIES['security']:
                self.event_filter.clear_type_filter()
            else:
                self.event_filter.set_category_filter('security')
        elif key == ord('f'):
            if self.event_filter.event_types == EVENT_CATEGORIES['file']:
                self.event_filter.clear_type_filter()
            else:
                self.event_filter.set_category_filter('file')
        elif key == ord('v'):
            if self.event_filter.event_types == EVENT_CATEGORIES['privilege']:
                self.event_filter.clear_type_filter()
            else:
                self.event_filter.set_category_filter('privilege')
        elif key == 27:  # ESC
            self.event_filter.clear_all()
        elif key == ord('r'):
            self.stats.reset()

    def run(self):
        """Main event loop."""
        self.initialize()

        while self.running:
            # Get terminal size
            height, width = self.stdscr.getmaxyx()

            # Calculate panel sizes (20%, 70%, 10%)
            stats_height = max(8, int(height * 0.20))
            status_height = max(5, int(height * 0.10))
            events_height = height - stats_height - status_height

            # Create windows
            stats_win = curses.newwin(stats_height, width, 0, 0)
            events_win = curses.newwin(events_height, width, stats_height, 0)
            status_win = curses.newwin(status_height, width, stats_height + events_height, 0)

            # Read new events
            if not self.paused:
                new_events = self.reader.read_new_events()
                for event in new_events:
                    self.stats.add_event(event)
                    if self.event_filter.matches(event):
                        self.events.append(event)

            # Render panels
            self.render_stats(stats_win, stats_height, width)
            self.render_events(events_win, events_height, width)
            self.render_status(status_win, status_height, width)

            # Handle input
            key = self.stdscr.getch()
            if key != -1:
                self.handle_input(key)

            # Small delay
            time.sleep(0.1)


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="LinMon Real-Time Monitoring Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Keyboard shortcuts:
  q           - Quit
  Space       - Pause/resume event stream
  p/n/s/f/v   - Filter by event category (Process/Network/Security/File/priVilege)
  Esc         - Clear all filters
  r           - Reset statistics counters

Examples:
  %(prog)s                          # Monitor default log file
  %(prog)s /var/log/linmon/events.json
        """
    )

    parser.add_argument(
        "log_file",
        nargs="?",
        default="/var/log/linmon/events.json",
        help="Path to LinMon log file (default: /var/log/linmon/events.json)"
    )

    args = parser.parse_args()
    log_path = Path(args.log_file)

    # Check dependencies
    try:
        from rich.console import Console
    except ImportError:
        print("Error: python3-rich not found.", file=sys.stderr)
        print("Install with: sudo apt-get install python3-rich", file=sys.stderr)
        sys.exit(1)

    # Run dashboard
    try:
        curses.wrapper(lambda stdscr: Dashboard(stdscr, log_path).run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
