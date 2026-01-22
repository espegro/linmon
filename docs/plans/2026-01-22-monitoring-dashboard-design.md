# LinMon Monitoring Dashboard Design

**Date:** 2026-01-22
**Type:** New Feature
**Target:** Real-time monitoring dashboard for LinMon events

## Overview

A top/htop-like terminal dashboard for monitoring LinMon activity in real-time. Built with Python and Textual framework, providing live event streaming, aggregate statistics, and performance monitoring.

## Requirements

### Primary Use Cases
- Real-time activity statistics (events/sec, event type breakdown, top processes/users)
- Live event stream viewer with syntax highlighting and filtering
- LinMon performance monitoring (events processed, system health)

### Secondary Use Cases
- Security monitoring (spot suspicious activity)
- System activity overview (general understanding)
- Debugging/development (see events flow)

## Architecture

### Components

1. **LogReader**
   - Reads `/var/log/linmon/events.json` asynchronously
   - On startup: Parses last 1000 events using `tail -n 1000`
   - Switches to follow mode using Python file watching
   - Parses JSON lines and emits events to UI
   - Handles log rotation (inode change detection)

2. **StatsCollector**
   - Maintains rolling statistics
   - Events per second (1-second, 5-second, 60-second averages)
   - Event type breakdown (process, network, security, file, privilege)
   - Top 10 processes by event count
   - Top 10 users by event count
   - LinMon performance metrics (if available)

3. **EventFilter**
   - Event type filter (bitfield for performance)
   - Username substring matching
   - Maintains filtered event stream for display
   - AND logic for multiple active filters

4. **DashboardApp** (Textual application)
   - Three-panel layout
   - Keyboard event handling
   - Auto-refresh every 100ms
   - Terminal resize handling

### Technology Stack

- **Python 3.8+** (available on Ubuntu 24.04 and RHEL 9+)
- **Textual** - Modern TUI framework
- **Rich** - Text formatting (dependency of Textual)
- No compilation required, pure Python

## UI Layout

### Three-Panel Design (similar to htop)

**Top Panel - Statistics (20% height):**
```
Events/sec: 12.4 (1s) | 8.2 (5s) | 15.6 (60s)
Process: ████░░░░░░ 45%  Network: ██░░░░░░░░ 20%  Security: █░░░░░░░░░ 10%
Top: bash(142) vim(89) ssh(34) | Users: alice(201) bob(64)
```

**Middle Panel - Event Stream (70% height):**
```
Time     | Type      | User  | Process | Details
19:42:15 | EXEC      | alice | bash    | /bin/bash -c "ls -la"
19:42:16 | TCP_CONN  | bob   | ssh     | 192.168.1.10:22
19:42:17 | PTRACE    | alice | gdb     | target_pid=1234 [SECURITY]
```

**Bottom Panel - Status Bar (10% height):**
```
Filters: [Security Events] [User: alice] | q:Quit Space:Pause p:Process n:Network s:Security u:User Esc:Clear
LinMon: Running | Log: /var/log/linmon/events.json
```

### Color Coding

- **Process events:** Blue
- **Network events:** Cyan
- **Security events:** Red (bold)
- **Privilege events:** Yellow
- **File events:** Green
- **Event rate:** Green (<50/s), Yellow (<100/s), Red (>100/s)

## User Controls

### Keyboard Shortcuts

**Filtering:**
- `p` - Toggle process events filter
- `n` - Toggle network events filter
- `s` - Toggle security events filter
- `f` - Toggle file events filter
- `v` - Toggle privilege events filter (v for priVilege)
- `u` - Activate username search (type to filter)
- `Esc` - Clear all filters

**Navigation:**
- `Space` - Pause/resume event stream
- `Up/Down` - Scroll event stream
- `Home/End` - Jump to top/bottom
- `r` - Reset statistics counters

**Control:**
- `q` or `Ctrl+C` - Quit application

### Filter Behavior

- Event type filters toggle on/off (press again to disable)
- Multiple filters combine with AND logic
- Username filter: partial substring match (case-sensitive)
- Status bar shows active filters
- Filtering doesn't affect statistics (stats count all events)

## Error Handling

### Log File Issues

1. **File not found:**
   - Show warning: `⚠ Log file not found: /var/log/linmon/events.json`
   - Poll every 5 seconds for file creation
   - Dashboard remains functional

2. **Permission denied:**
   - Show error: `✗ Permission denied. Try: sudo chmod +r /var/log/linmon/events.json`
   - Suggest permission fix (don't recommend sudo - would show wrong stats)

3. **Log rotation:**
   - Detect inode change
   - Automatically reopen new file
   - Show notification: `Log rotated, reopened`

4. **Malformed JSON:**
   - Skip invalid lines
   - Count errors: `⚠ 3 malformed events skipped`
   - Log to stderr for debugging

### Performance Safeguards

1. **High event rate (>1000/sec):**
   - Enable sampling mode (show every Nth event)
   - Warning: `⚠ High load - sampling 1 in 10 events`
   - Statistics continue counting all events

2. **Memory limits:**
   - Keep only last 500 events in display buffer
   - Older events automatically dropped
   - Prevents memory growth on long-running sessions

3. **Terminal resize:**
   - Handled automatically by Textual framework
   - Panels adjust proportionally

## Implementation

### File Location

```
scripts/linmon-monitor.py   # Main executable (chmod +x)
```

### Command Line Interface

```bash
# Default log file path
./linmon-monitor.py

# Custom log file path
./linmon-monitor.py /path/to/events.json

# Help
./linmon-monitor.py --help
```

### Dependencies

```bash
pip3 install textual rich
```

### Code Structure

- **~300-400 lines total** (single file)
- Type hints for all functions
- Docstrings for classes
- Clean separation of concerns:
  - `LogReader` class (~80 lines)
  - `StatsCollector` class (~60 lines)
  - `EventFilter` class (~40 lines)
  - `StatsPanel` widget (~50 lines)
  - `EventStreamPanel` widget (~60 lines)
  - `StatusBar` widget (~30 lines)
  - `DashboardApp` main app (~50 lines)
  - Helper functions (~30 lines)

### Testing Plan

1. **Basic functionality:**
   - Run against existing `/var/log/linmon/events.json`
   - Verify all three panels render correctly
   - Test all keyboard shortcuts

2. **Filtering:**
   - Test each event type filter
   - Test username filter with partial matches
   - Test filter combinations
   - Verify status bar updates

3. **High volume:**
   - Generate heavy activity (compile, run tests)
   - Verify no lag or dropped updates
   - Confirm sampling mode activates if needed

4. **Edge cases:**
   - Delete log file while running
   - Create malformed JSON lines
   - Resize terminal to very small size
   - Log rotation during monitoring

5. **Cross-platform:**
   - Test on Ubuntu 24.04 (Python 3.12)
   - Test on RHEL 9 (Python 3.9)
   - Test on Rocky 10 (Python 3.9)

## Non-Goals

- **Historical analysis** - Not designed for parsing old logs (use `linmon-report.sh` for that)
- **Export/save** - No save-to-file functionality (can use tee or script command if needed)
- **Complex queries** - No regex or advanced search (use jq on log file directly)
- **Remote monitoring** - Only local log file (can use SSH port forwarding if needed)

## Future Enhancements (Not in Initial Version)

- Configurable refresh rate
- Color scheme customization
- Export filtered events to file
- Alert thresholds with visual/audio notifications
- Graph view for event rate over time
- Container filter (show only container events)
