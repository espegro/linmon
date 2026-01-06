# LinMon Monitoring Guide

This guide provides practical examples for monitoring, analyzing, and alerting on LinMon events.

## Table of Contents
- [Quick Start Queries](#quick-start-queries)
- [Event Types](#event-types)
- [Common Analysis Patterns](#common-analysis-patterns)
- [Integration with Monitoring Systems](#integration-with-monitoring-systems)
- [Alerting Examples](#alerting-examples)
- [Performance Monitoring](#performance-monitoring)
- [Troubleshooting](#troubleshooting)

## Quick Start Queries

All queries assume logs are at `/var/log/linmon/events.json` in JSON Lines format.

### View Last 10 Events
```bash
tail -10 /var/log/linmon/events.json | jq
```

### Follow Events in Real-Time
```bash
tail -f /var/log/linmon/events.json | jq
```

### Count Events by Type
```bash
cat /var/log/linmon/events.json | jq -r '.type' | sort | uniq -c | sort -rn
```

### Find All sudo Usage
```bash
grep '"type":"priv_sudo"' /var/log/linmon/events.json | jq
```

### Show All Process Executions by User
```bash
grep '"type":"process_exec"' /var/log/linmon/events.json | \
  jq -r '[.timestamp, .username, .cmdline] | @tsv' | column -t
```

### Track User Activity Across sudo
```bash
# Show all activity by a user (including commands run via sudo)
grep '"type":"process_exec"' /var/log/linmon/events.json | \
  jq 'select(.uid == 1000 or .sudo_uid == 1000)'

# List commands run as root by each sudo user
grep '"type":"process_exec"' /var/log/linmon/events.json | \
  jq -r 'select(.sudo_uid) | [.timestamp, .sudo_user, .cmdline] | @tsv' | column -t
```

## Event Types

LinMon logs the following event types:

### Process Events
- `process_exec` - Process execution (fork/exec)
- `process_exit` - Process termination

**Fields**:
```json
{
  "timestamp": "2024-11-30T10:15:30.123Z",
  "type": "process_exec",
  "pid": 12345,
  "ppid": 1234,
  "uid": 0,
  "username": "root",
  "sudo_uid": 1000,
  "sudo_user": "alice",
  "comm": "bash",
  "filename": "/usr/bin/bash",
  "cmdline": "/bin/bash -c ls",
  "sha256": "abc123...",
  "package": "bash",
  "pkg_modified": false
}
```

**Package Verification Fields** (requires `verify_packages = true`):
- `package` - Package name if binary belongs to system package (dpkg/rpm), or `null` if not from a package
- `pkg_modified` - Only present and `true` if file was modified since package installation

### Network Events
- `net_connect_tcp` - Outbound TCP connection
- `net_accept_tcp` - Inbound TCP connection accepted
- `net_send_udp` - UDP packet sent
- `net_vsock_connect` - vsock (VM/container) connection (requires `monitor_vsock=true`)

**Fields (TCP/UDP)**:
```json
{
  "timestamp": "2024-11-30T10:15:30.123Z",
  "type": "net_connect_tcp",
  "pid": 12345,
  "uid": 1000,
  "username": "alice",
  "comm": "curl",
  "saddr": "192.168.1.100",
  "daddr": "1.1.1.1",
  "sport": 54321,
  "dport": 443,
  "family": 2
}
```

**Fields (vsock)**:
```json
{
  "timestamp": "2024-12-28T19:15:42.123Z",
  "type": "net_vsock_connect",
  "pid": 5432,
  "uid": 1000,
  "username": "alice",
  "comm": "vm_app",
  "saddr": "3",
  "daddr": "2",
  "sport": 12345,
  "dport": 2049,
  "family": 40
}
```

> **Note**: vsock events use CIDs (Context IDs) instead of IP addresses. CID 2 is typically the host, CID 3+ are VMs/containers.

### File Events
- `file_open` - File opened
- `file_create` - File created
- `file_delete` - File deleted
- `file_modify` - File modified

**Fields**:
```json
{
  "timestamp": "2024-11-30T10:15:30.123Z",
  "type": "file_create",
  "pid": 12345,
  "uid": 1000,
  "username": "alice",
  "comm": "vim",
  "filename": "/home/alice/document.txt",
  "flags": 577
}
```

### Privilege Events
- `priv_setuid` - UID change (e.g., su, sudo)
- `priv_setgid` - GID change
- `priv_sudo` - sudo command execution

**Fields**:
```json
{
  "timestamp": "2024-11-30T10:15:30.123Z",
  "type": "priv_sudo",
  "pid": 12345,
  "old_uid": 1000,
  "old_username": "alice",
  "new_uid": 0,
  "new_username": "root",
  "old_gid": 1000,
  "new_gid": 0,
  "comm": "sudo",
  "target": "apt"
}
```

### Security Events (MITRE ATT&CK)

LinMon detects various attack techniques mapped to the MITRE ATT&CK framework.

#### Credential File Access (T1003.008)
- `security_cred_read` - Suspicious read of authentication/authorization files

Monitors reads of sensitive files by non-whitelisted processes:
- `/etc/shadow`, `/etc/gshadow` - Password hashes
- `/etc/sudoers`, `/etc/sudoers.d/*` - Sudo configuration
- `/etc/ssh/*` - SSH configuration, authorized_keys
- `/etc/pam.d/*` - PAM authentication configuration

**Fields**:
```json
{
  "timestamp": "2024-12-23T10:15:30.123Z",
  "type": "security_cred_read",
  "pid": 12345,
  "uid": 1000,
  "username": "attacker",
  "comm": "cat",
  "cred_file": "shadow",
  "path": "/etc/shadow",
  "open_flags": 0
}
```

**cred_file values**: `shadow`, `gshadow`, `sudoers`, `ssh_config`, `pam_config`

#### LD_PRELOAD Hijacking (T1574.006)
- `security_ldpreload` - Write attempt to /etc/ld.so.preload

**Fields**:
```json
{
  "timestamp": "2024-12-23T10:15:30.123Z",
  "type": "security_ldpreload",
  "pid": 12345,
  "uid": 0,
  "comm": "malware",
  "path": "/etc/ld.so.preload",
  "open_flags": 577
}
```

#### Other Security Events
- `security_ptrace` - T1055 Process Injection (debugger attachment)
- `security_module_load` - T1547.006 Kernel Module Loading
- `security_memfd_create` - T1620 Fileless Malware (anonymous memory execution)
- `security_bind` - T1571 Bind Shell / C2 Server Detection
- `security_unshare` - T1611 Container Escape (namespace manipulation)
- `security_execveat` - T1620 Fileless Execution (fd-based exec)
- `security_bpf` - T1014 eBPF Rootkit Detection

### Process Masquerading Detection Fields

LinMon adds two security-focused fields to detect suspicious process behavior:

#### comm_mismatch
**Type**: boolean (only present when true)
**Event types**: network events, privilege events, security events
**Description**: Detects when a process changes its comm name to masquerade as another program

**Detection method**:
- Compares kernel comm name (from `task_struct->comm`) with actual executable path
- Reads `/proc/<pid>/exe` symlink to get real executable basename
- Smart prefix matching: handles 15-char TASK_COMM_LEN truncation
- Only logged when mismatch detected

**Example**:
```json
{
  "type": "net_connect_tcp",
  "comm": "systemd",
  "process_name": "backdoor",
  "comm_mismatch": true,
  "daddr": "198.51.100.1"
}
```

**SIEM query** (Elasticsearch/Splunk):
```
comm_mismatch:true AND (filename:/tmp/* OR filename:/dev/shm/* OR package:null)
```

#### deleted_executable
**Type**: boolean (only present when true)
**Event types**: network events, privilege events, security events
**Description**: Detects when a process executable has been deleted from disk

**Detection method**:
- Reads `/proc/<pid>/exe` symlink marked with ` (deleted)` suffix
- Indicates fileless execution or post-exploitation cleanup
- Only logged when detected

**Example**:
```json
{
  "type": "net_connect_tcp",
  "comm": "malware",
  "process_name": "malware",
  "deleted_executable": true,
  "daddr": "198.51.100.1"
}
```

**SIEM query** (Elasticsearch/Splunk):
```
deleted_executable:true
```

**Note**: Process exec events (`process_exec`) already have `filename` and `process_name` fields from eBPF capture at exec time. These new fields apply to post-exec events (network, privilege, security) where the process name must be read from `/proc`.

## Common Analysis Patterns

### Security Monitoring

#### Detect Privilege Escalation
```bash
# All sudo usage
grep '"type":"priv_sudo"' /var/log/linmon/events.json | \
  jq -r '[.timestamp, .old_username, .target] | @tsv'

# Failed sudo attempts (requires auditd integration)
# Look for sudo exec followed by immediate exit
```

#### Suspicious Network Connections
```bash
# Connections to non-standard ports
grep '"type":"net_connect_tcp"' /var/log/linmon/events.json | \
  jq 'select(.dport != 80 and .dport != 443 and .dport != 22)'

# Connections from unexpected processes
grep '"type":"net_connect_tcp"' /var/log/linmon/events.json | \
  jq 'select(.comm | test("curl|wget|python|perl|nc"))'
```

#### Suspicious Process Execution
```bash
# Processes with "password" in command line (despite redaction)
grep '"type":"process_exec"' /var/log/linmon/events.json | \
  jq 'select(.cmdline | test("password|token|secret"; "i"))'

# Shells spawned by web servers
grep '"type":"process_exec"' /var/log/linmon/events.json | \
  jq 'select(.comm | test("sh|bash") and (.filename | test("apache|nginx|php")))'
```

#### Binary Integrity Monitoring
```bash
# Track unique binaries executed by hash
grep '"type":"process_exec"' /var/log/linmon/events.json | \
  jq -r 'select(.sha256) | [.filename, .sha256] | @tsv' | \
  sort -u > known_binaries.txt

# Alert on unknown binaries
grep '"type":"process_exec"' /var/log/linmon/events.json | \
  jq -r 'select(.sha256) | [.filename, .sha256] | @tsv' | \
  grep -v -F -f known_binaries.txt
```

#### Untrusted/Unpackaged Binary Detection
```bash
# Find binaries NOT from system packages (requires verify_packages = true)
grep '"type":"process_exec"' /var/log/linmon/events.json | \
  jq 'select(.package == null)'

# List all unpackaged binaries by path
grep '"type":"process_exec"' /var/log/linmon/events.json | \
  jq -r 'select(.package == null) | .filename' | sort -u

# Detect modified package files (potential tampering)
grep '"type":"process_exec"' /var/log/linmon/events.json | \
  jq 'select(.pkg_modified == true)'

# Summary: trusted vs untrusted binaries
grep '"type":"process_exec"' /var/log/linmon/events.json | \
  jq -r 'if .package then "packaged" else "unpackaged" end' | \
  sort | uniq -c
```

#### Credential File Access Detection
```bash
# All credential file access attempts
grep '"type":"security_cred_read"' /var/log/linmon/events.json | jq

# Shadow file reads (password hash theft)
grep '"type":"security_cred_read"' /var/log/linmon/events.json | \
  jq 'select(.cred_file == "shadow")'

# SSH config reconnaissance
grep '"type":"security_cred_read"' /var/log/linmon/events.json | \
  jq 'select(.cred_file == "ssh_config")'

# Sudoers file access (privilege escalation recon)
grep '"type":"security_cred_read"' /var/log/linmon/events.json | \
  jq 'select(.cred_file == "sudoers")'
```

#### Rootkit Detection
```bash
# LD_PRELOAD hijacking attempts
grep '"type":"security_ldpreload"' /var/log/linmon/events.json | jq

# Kernel module loading (rootkit installation)
grep '"type":"security_module_load"' /var/log/linmon/events.json | jq

# eBPF program loading (potential eBPF rootkit)
grep '"type":"security_bpf"' /var/log/linmon/events.json | jq
```

#### Fileless Malware Detection
```bash
# memfd_create usage (in-memory execution)
grep '"type":"security_memfd_create"' /var/log/linmon/events.json | jq

# execveat usage (fd-based execution)
grep '"type":"security_execveat"' /var/log/linmon/events.json | jq

# Correlation: memfd followed by execveat (fileless attack chain)
grep -E '"type":"security_(memfd|execveat)"' /var/log/linmon/events.json | \
  jq -r '[.timestamp, .type, .pid, .comm] | @tsv'
```

### User Activity Tracking

#### User Session Timeline
```bash
# All activity for user "alice"
grep '"username":"alice"' /var/log/linmon/events.json | \
  jq -r '[.timestamp, .type, .comm, .cmdline // .filename // ""] | @tsv' | \
  column -t
```

#### Most Active Users
```bash
jq -r '.username // "unknown"' /var/log/linmon/events.json | \
  sort | uniq -c | sort -rn | head -10
```

#### Login Detection
```bash
# SSH logins (look for sshd accepting connections then spawning shell)
grep '"comm":"sshd"' /var/log/linmon/events.json | \
  grep '"type":"net_accept_tcp"'
```

### Performance & Debugging

#### Event Volume Over Time
```bash
# Events per hour
jq -r '.timestamp[:13]' /var/log/linmon/events.json | \
  sort | uniq -c | sort
```

#### Noisiest Processes
```bash
jq -r '.comm' /var/log/linmon/events.json | \
  sort | uniq -c | sort -rn | head -20
```

#### Network Bandwidth Estimation
```bash
# TCP connections per minute
grep '"type":"net_connect_tcp"' /var/log/linmon/events.json | \
  jq -r '.timestamp[:16]' | sort | uniq -c
```

## Integration with Monitoring Systems

### Elasticsearch / ELK Stack

**Filebeat configuration** (`/etc/filebeat/filebeat.yml`):
```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/linmon/events.json
  json.keys_under_root: true
  json.add_error_key: true
  fields:
    log_type: linmon

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "linmon-%{+yyyy.MM.dd}"

setup.template.name: "linmon"
setup.template.pattern: "linmon-*"
```

**Kibana queries**:
```
# Privilege escalation
type:priv_sudo

# Suspicious network activity
type:net_connect_tcp AND NOT dport:(80 OR 443 OR 22)

# Binary changes
type:process_exec AND sha256:*
```

### Grafana / Prometheus

LinMon doesn't expose metrics directly. Use a log-to-metrics exporter:

**Example with mtail** (`/etc/mtail/linmon.mtail`):
```python
counter linmon_events_total by type
counter linmon_process_execs by comm
counter linmon_network_connections by dport

/type":"([^"]+)"/ {
  linmon_events_total[$1]++
}

/type":"process_exec".*"comm":"([^"]+)"/ {
  linmon_process_execs[$1]++
}

/type":"net_connect_tcp".*"dport":(\d+)/ {
  linmon_network_connections[$1]++
}
```

**Grafana dashboard queries**:
```promql
# Events per second
rate(linmon_events_total[5m])

# Top processes by execution count
topk(10, rate(linmon_process_execs[5m]))

# Network connections by port
sum by (dport) (rate(linmon_network_connections[5m]))
```

### Splunk

**inputs.conf**:
```ini
[monitor:///var/log/linmon/events.json]
disabled = false
sourcetype = linmon:json
index = security
```

**Example queries**:
```spl
# Privilege escalation timeline
index=security sourcetype=linmon:json type=priv_sudo
| timechart count by old_username

# Suspicious network connections
index=security sourcetype=linmon:json type=net_connect_tcp
| where dport!=80 AND dport!=443 AND dport!=22
| stats count by comm daddr dport

# Binary execution frequency
index=security sourcetype=linmon:json type=process_exec
| stats count by filename sha256
| sort -count
```

## Alerting Examples

### systemd Journal Alerts

Monitor for specific patterns in real-time:

```bash
#!/bin/bash
# /usr/local/bin/linmon-alerter.sh

tail -F /var/log/linmon/events.json | while read -r line; do
    # Alert on sudo to root
    if echo "$line" | jq -e '.type == "priv_sudo" and .new_uid == 0' >/dev/null; then
        user=$(echo "$line" | jq -r .old_username)
        target=$(echo "$line" | jq -r .target)
        logger -t linmon-alert "ALERT: User $user executed sudo $target"
    fi

    # Alert on SSH from unexpected IPs
    if echo "$line" | jq -e '.comm == "sshd" and .type == "net_accept_tcp"' >/dev/null; then
        saddr=$(echo "$line" | jq -r .saddr)
        if ! echo "$saddr" | grep -q '^192\.168\.'; then
            logger -t linmon-alert "ALERT: SSH connection from external IP: $saddr"
        fi
    fi
done
```

### Email Alerts (with mail)

```bash
#!/bin/bash
# /usr/local/bin/linmon-email-alert.sh

ALERT_EMAIL="admin@example.com"
ALERT_THRESHOLD=10  # Alert if >10 sudo in 5 minutes

while true; do
    count=$(grep '"type":"priv_sudo"' /var/log/linmon/events.json | \
            tail -n 100 | \
            jq -r '.timestamp' | \
            awk -v cutoff="$(date -d '5 minutes ago' -Iseconds)" '$1 > cutoff' | \
            wc -l)

    if [ "$count" -gt "$ALERT_THRESHOLD" ]; then
        echo "Alert: $count sudo commands in last 5 minutes" | \
            mail -s "LinMon Alert: High sudo activity" "$ALERT_EMAIL"
    fi

    sleep 60
done
```

### Slack Webhook

```bash
#!/bin/bash
# /usr/local/bin/linmon-slack.sh

SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

send_slack() {
    local message="$1"
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"$message\"}" \
        "$SLACK_WEBHOOK"
}

tail -F /var/log/linmon/events.json | while read -r line; do
    # Alert on new binary execution
    if echo "$line" | jq -e '.type == "process_exec" and .sha256' >/dev/null; then
        filename=$(echo "$line" | jq -r .filename)
        sha256=$(echo "$line" | jq -r .sha256)
        user=$(echo "$line" | jq -r .username)

        send_slack "🔍 New binary executed: \`$filename\` by $user (SHA256: ${sha256:0:16}...)"
    fi
done
```

## Performance Monitoring

### Check LinMon Health

```bash
#!/bin/bash
# /usr/local/bin/linmon-health.sh

# Check if daemon is running
if ! systemctl is-active --quiet linmond; then
    echo "ERROR: LinMon daemon not running"
    exit 1
fi

# Check log file is being written
if [ ! -f /var/log/linmon/events.json ]; then
    echo "ERROR: Log file missing"
    exit 1
fi

# Check last event timestamp
last_event=$(tail -1 /var/log/linmon/events.json | jq -r .timestamp)
last_epoch=$(date -d "$last_event" +%s 2>/dev/null || echo 0)
now_epoch=$(date +%s)
age=$((now_epoch - last_epoch))

if [ "$age" -gt 300 ]; then
    echo "WARNING: Last event is $age seconds old"
    exit 1
fi

echo "OK: LinMon healthy, last event $age seconds ago"
exit 0
```

### Log Volume Monitoring

```bash
# Events per second (last minute)
events_per_sec=$(tail -n 1000 /var/log/linmon/events.json | \
    jq -r '.timestamp' | \
    awk -v cutoff="$(date -d '1 minute ago' -Iseconds)" '$1 > cutoff' | \
    wc -l)
echo "Events/sec: $((events_per_sec / 60))"

# Log file growth rate
current_size=$(stat -f%z /var/log/linmon/events.json)
sleep 60
new_size=$(stat -f%z /var/log/linmon/events.json)
growth=$((new_size - current_size))
echo "Log growth: $((growth / 1024)) KB/min"
```

### Kernel eBPF Stats

```bash
# Check BPF program stats (requires root)
sudo bpftool prog show | grep linmon

# Check BPF map stats
sudo bpftool map show | grep -A5 linmon
```

## Troubleshooting

### No Events Being Logged

```bash
# 1. Check daemon is running
sudo systemctl status linmond

# 2. Check for errors
sudo journalctl -u linmond -n 50 --no-pager

# 3. Test with known activity
ls /tmp
grep "$(whoami)" /var/log/linmon/events.json | tail -5

# 4. Check UID filtering
id  # Check your UID
grep min_uid /etc/linmon/linmon.conf  # Should be <= your UID
```

### Too Many Events

```bash
# 1. Identify noisy processes
jq -r '.comm' /var/log/linmon/events.json | \
  sort | uniq -c | sort -rn | head -20

# 2. Add to ignore_processes in config
echo "ignore_processes = chrome,firefox,systemd" | \
  sudo tee -a /etc/linmon/linmon.conf

# 3. Reload config
sudo systemctl reload linmond

# 4. Enable thread filtering
sudo sed -i 's/ignore_threads = false/ignore_threads = true/' /etc/linmon/linmon.conf
sudo systemctl reload linmond
```

### Log Rotation Issues

```bash
# 1. Test logrotate config
sudo logrotate -d /etc/logrotate.d/linmond

# 2. Force rotation
sudo logrotate -f /etc/logrotate.d/linmond

# 3. Check permissions
ls -la /var/log/linmon/

# 4. Verify reload worked
sudo journalctl -u linmond | grep "reopened"
```

### High CPU Usage

```bash
# 1. Check event rate
tail -f /var/log/linmon/events.json | pv -l -i 1 > /dev/null

# 2. If too high, add filters to reduce event volume
# eBPF rate limit: 200 events/sec/UID (50 burst)
# Reduce by filtering in config

# 3. Disable expensive features
sudo sed -i 's/hash_binaries = true/hash_binaries = false/' /etc/linmon/linmon.conf
sudo systemctl reload linmond
```

### Disk Full

```bash
# 1. Check log size
du -sh /var/log/linmon/

# 2. Adjust logrotate retention
sudo vi /etc/logrotate.d/linmond
# Change: rotate 30 → rotate 7 (keep only 7 days)

# 3. Force cleanup
sudo logrotate -f /etc/logrotate.d/linmond

# 4. Consider reducing event volume (see "Too Many Events" above)
```

## Best Practices

1. **Start with minimal monitoring**, then expand:
   - Begin with `monitor_processes=true`, everything else `false`
   - Enable features incrementally based on needs

2. **Use filtering aggressively**:
   - Set `min_uid=1000` to ignore system users
   - Use `ignore_processes` for noisy applications
   - Enable `ignore_threads=true` to reduce browser/GUI noise

3. **Monitor the monitor**:
   - Set up health checks for LinMon itself
   - Alert on log file growth anomalies
   - Track events/sec metrics

4. **Secure the logs**:
   - Logs contain sensitive data (command lines, network activity)
   - Restrict access: `chmod 640 /var/log/linmon/events.json`
   - Consider encrypting archived logs

5. **Regular analysis**:
   - Review top processes weekly
   - Establish baseline for normal activity
   - Alert on deviations from baseline

6. **Integration**:
   - Send logs to SIEM (Splunk, ELK, etc.)
   - Create dashboards for visibility
   - Set up automated alerts for security events

## Example Dashboards

### Simple Bash Dashboard

```bash
#!/bin/bash
# /usr/local/bin/linmon-dashboard.sh

clear
echo "=== LinMon Dashboard ==="
echo "Time: $(date)"
echo

echo "Events (last hour):"
jq -r '.timestamp[:13]' /var/log/linmon/events.json | \
  tail -n 10000 | sort | uniq -c | tail -5

echo
echo "Top Processes:"
jq -r '.comm' /var/log/linmon/events.json | \
  tail -n 1000 | sort | uniq -c | sort -rn | head -10

echo
echo "Active Users:"
jq -r '.username // "system"' /var/log/linmon/events.json | \
  tail -n 1000 | sort | uniq -c | sort -rn | head -10

echo
echo "Recent Privilege Escalations:"
grep '"type":"priv_sudo"' /var/log/linmon/events.json | \
  tail -5 | jq -r '[.timestamp, .old_username, .target] | @tsv' | column -t
```

Run with: `watch -n 5 /usr/local/bin/linmon-dashboard.sh`
