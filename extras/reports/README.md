# LinMon Reporting Scripts

This directory contains report generation scripts for analyzing LinMon event logs.

## Scripts

### daily-report.sh

Generates a comprehensive daily statistics report from LinMon event logs.

**Features**:
- Event summary by type
- Top 10 most active users
- Top 10 most executed processes
- Network activity statistics (TCP/UDP)
- Top 10 network destinations
- Security events (if any)
- Privilege escalation statistics
- File activity statistics
- Tamper detection (sequence gap analysis)
- Hourly event distribution

**Usage**:
```bash
# Generate report for last 24 hours (default)
./daily-report.sh

# Generate report for last 12 hours
./daily-report.sh 12

# Generate report for last 48 hours from custom log directory
./daily-report.sh 48 /custom/log/path
```

**Parameters**:
- `hours` - Number of hours to analyze (default: 24)
- `log_dir` - Path to log directory (default: /var/log/linmon)

**Example Output**:
```
═══════════════════════════════════════════════════════
    LinMon Daily Report - Last 24 Hours
═══════════════════════════════════════════════════════

Report generated: Fri Dec 27 14:30:00 UTC 2025
Time range: 2025-12-26T14:30:00Z to 2025-12-27T14:30:00Z
Log directory: /var/log/linmon

Event Summary by Type:
────────────────────────────────────────────────────────
  process_exec                      12345
  net_connect_tcp                    5678
  process_exit                       4321
  net_send_udp                       1234

Total Events: 23578

Top 10 Most Active Users:
────────────────────────────────────────────────────────
  alice                             15234 events
  bob                                8344 events

Top 10 Most Executed Processes:
────────────────────────────────────────────────────────
  bash                               1234 executions
  git                                 567 executions
  python3                             234 executions

Network Activity:
────────────────────────────────────────────────────────
  TCP connections (outbound): 5678
  TCP accepts (inbound):      123
  UDP sends:                  1234

Tamper Detection:
────────────────────────────────────────────────────────
  ✓ No sequence gaps detected

Report complete.
```

### security-report.sh

Generates a security-focused analysis report with MITRE ATT&CK event detection.

**Features**:
- MITRE ATT&CK security event analysis:
  - T1055: Process Injection (ptrace)
  - T1547.006: Kernel Module Loading
  - T1620: Fileless Malware (memfd_create)
  - T1571: Bind Shell / C2 Server
  - T1611: Container Escape (unshare)
  - T1620: Fileless Execution (execveat)
  - T1014: eBPF Rootkit
  - T1003.008: Credential File Access
  - T1574.006: LD_PRELOAD Hijacking
- Privilege escalation analysis
- Sudo usage by user
- Root shell sessions
- Network security analysis
- Suspicious port detection (4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345)
- Non-standard port connections
- Tamper detection (sequence gaps, daemon lifecycle)
- Comprehensive security summary

**Usage**:
```bash
# Generate security report for last 24 hours (default)
./security-report.sh

# Generate security report for last 12 hours
./security-report.sh 12

# Generate security report for last 48 hours from custom log directory
./security-report.sh 48 /custom/log/path
```

**Parameters**:
- `hours` - Number of hours to analyze (default: 24)
- `log_dir` - Path to log directory (default: /var/log/linmon)

**Example Output**:
```
═══════════════════════════════════════════════════════
    LinMon Security Report - Last 24 Hours
═══════════════════════════════════════════════════════

Report generated: Fri Dec 27 14:30:00 UTC 2025
Time range: 2025-12-26T14:30:00Z to 2025-12-27T14:30:00Z

════════════════════════════════════════════════════════
  MITRE ATT&CK Security Events
════════════════════════════════════════════════════════

🔴 T1571 - Bind Shell / C2 Server: 2 events
────────────────────────────────────────────────────────
  [14:25:12] User: attacker Process: nc Port: 4444
  [15:30:45] User: suspicious Process: python3 Port: 8888

════════════════════════════════════════════════════════
  Privilege Escalation Analysis
════════════════════════════════════════════════════════

Sudo Usage by User:
────────────────────────────────────────────────────────
  UID 1000        234 sudo calls
  UID 1001         45 sudo calls

════════════════════════════════════════════════════════
  Network Security Analysis
════════════════════════════════════════════════════════

Connections to Suspicious Ports:
────────────────────────────────────────────────────────
  Port 4444: 2 connections
    [14:25:12] nc → 192.168.1.100:4444

════════════════════════════════════════════════════════
  Tamper Detection & Integrity
════════════════════════════════════════════════════════

✓ No sequence gaps detected - log integrity OK

Daemon Lifecycle Events:
────────────────────────────────────────────────────────
  Daemon starts:    1
  Config reloads:   0
  Daemon shutdowns: 0

════════════════════════════════════════════════════════
  Security Summary
════════════════════════════════════════════════════════

⚠ 2 security events detected
  Review events above for potential threats.

Report complete. Review all events marked with 🔴 for immediate action.
```

## Requirements

Both scripts require:
- **jq** - Command-line JSON processor
  ```bash
  # Ubuntu/Debian
  sudo apt-get install jq

  # RHEL/Rocky/AlmaLinux
  sudo dnf install jq
  ```

## Features Common to Both Scripts

### Multi-Log Support
Both scripts automatically read:
- Current log: `/var/log/linmon/events.json`
- Rotated logs: `/var/log/linmon/events.json.1`, `events.json.2`, etc.

This ensures complete coverage even when logs have been rotated.

### Time Filtering
Events are filtered by timestamp to only include the specified time range (last N hours).

### Color-Coded Output
- **RED**: Critical security events requiring immediate action
- **YELLOW**: Warnings and suspicious activity
- **GREEN**: Normal status and OK indicators
- **BLUE**: Informational headers

### Graceful Error Handling
- Missing log files: Scripts continue without errors
- Invalid JSON: Silently skipped
- Missing jq: Clear error message with installation instructions

## Automated Reporting

### Daily Reports via Cron

Generate daily reports automatically:

```bash
# Edit crontab
crontab -e

# Add daily report at 00:00 (midnight)
0 0 * * * /path/to/linmon/extras/reports/daily-report.sh 24 > /var/log/linmon/daily-report-$(date +\%Y-\%m-\%d).txt 2>&1

# Add security report at 00:05
5 0 * * * /path/to/linmon/extras/reports/security-report.sh 24 > /var/log/linmon/security-report-$(date +\%Y-\%m-\%d).txt 2>&1
```

### Weekly Reports

```bash
# Weekly report on Sundays at 01:00
0 1 * * 0 /path/to/linmon/extras/reports/daily-report.sh 168 > /var/log/linmon/weekly-report-$(date +\%Y-\%W).txt 2>&1
```

### Email Reports

Send reports via email using mailx or sendmail:

```bash
#!/bin/bash
# Generate and email daily security report

REPORT_FILE=$(mktemp)
/path/to/linmon/extras/reports/security-report.sh 24 > "$REPORT_FILE"

if grep -q "security events detected" "$REPORT_FILE"; then
    mail -s "LinMon Security Report - $(hostname) - $(date +%Y-%m-%d)" \
         security@example.com < "$REPORT_FILE"
fi

rm "$REPORT_FILE"
```

Add to crontab:
```bash
0 8 * * * /path/to/email-security-report.sh
```

## Tamper Detection

Both scripts include **smart tamper detection** by checking for gaps in the `seq` (sequence number) field:

**How it works**:
1. Extract all `seq` values from events
2. Sort numerically
3. Check for gaps: if `seq[n+1] != seq[n] + 1`, analyze the gap size
4. **Distinguish between legitimate and suspicious gaps**:
   - **Large gaps (≥100)**: Daemon restart (sequence counter resets to 0) - **IGNORED**
   - **Small gaps (<100)**: Deleted events within a session - **FLAGGED AS TAMPERING**

**Why this is better than naive gap detection**:
- LinMon's sequence counter resets to 0 on every daemon restart
- Naive detection would flag every restart as "tampering" (false positives)
- Smart detection only flags **suspicious small gaps** that indicate deleted events
- Provides context: Reports number of daemon restarts to explain large jumps

**Example scenarios**:

✅ **Normal (no alert)**:
```
Sequences: 100, 101, 102, 1, 2, 3  (daemon restarted between 102 and 1)
Output: "No suspicious gaps detected. 2 daemon restarts in time range."
```

🔴 **Tampering (alert)**:
```
Sequences: 100, 101, 102, 150, 151  (events 103-149 deleted)
Output: "Gap: seq 103 to 149 (47 events missing) - This suggests deleted events."
```

**What to do if tampering is detected**:
1. Check syslog/journald for daemon lifecycle events:
   ```bash
   sudo journalctl -t linmond --since "1 day ago"
   ```
2. Verify daemon restarts align with large sequence jumps
3. Check for suspicious shutdowns with sender PID/UID
4. Compare event counts with checkpoint logs in syslog
5. If tampering confirmed, escalate to security team immediately

## Integration with Monitoring Systems

### Prometheus Metrics Export

Convert reports to Prometheus format:

```bash
#!/bin/bash
# prometheus-exporter.sh

METRICS_FILE="/var/lib/node_exporter/textfile_collector/linmon.prom"

# Generate metrics
cat > "$METRICS_FILE" <<EOF
# HELP linmon_events_total Total number of events in last 24h
# TYPE linmon_events_total counter
linmon_events_total $(grep '"type"' /var/log/linmon/events.json | wc -l)

# HELP linmon_security_events_total Security events detected in last 24h
# TYPE linmon_security_events_total counter
linmon_security_events_total $(grep '"security_' /var/log/linmon/events.json | wc -l)
EOF
```

### Grafana Dashboards

Use the JSON output to create Grafana dashboards with ClickHouse or Elasticsearch backend. See `extras/` directory for SIEM integration examples.

## Troubleshooting

**"Error: jq is required"**:
- Install jq: `sudo apt-get install jq` (Ubuntu) or `sudo dnf install jq` (RHEL)

**"Error: Log file not found"**:
- Verify log directory: `ls -la /var/log/linmon/`
- Check LinMon is running: `sudo systemctl status linmond`
- Check permissions: Scripts need read access to log files

**No events in report**:
- Check time range: Events may be outside the specified hours
- Verify events exist: `tail -5 /var/log/linmon/events.json`
- Check timestamp format: Scripts expect ISO 8601 UTC timestamps

**Reports show only partial data**:
- Check log rotation: Rotated logs should follow pattern `events.json.1`, `events.json.2`
- Verify glob pattern: `ls /var/log/linmon/events.json.*`
- Check for compressed logs: Scripts currently don't support `.gz` files

## License

These scripts are part of the LinMon project and are licensed under GPL-2.0.

## Contributing

Report issues or submit improvements at https://github.com/espegro/linmon/issues
