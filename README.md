# LinMon - Linux Activity Monitor

LinMon is a system monitoring service for Linux (Ubuntu/RHEL) that logs interactive user activity, similar to Sysmon for Windows. It uses eBPF (Extended Berkeley Packet Filter) to instrument the kernel with minimal overhead.

## Features

### Core Monitoring
- **Process Monitoring**: Track execution and termination with full command-line arguments
- **Network Monitoring**: TCP connections (connect/accept), UDP traffic with IPv4/IPv6 support, and vsock (VM/container) communication
- **File Monitoring**: Track file create, modify, delete operations
- **Privilege Escalation**: Detect setuid, setgid, and sudo usage

### Advanced Filtering
- **UID/GID Filtering**: Configurable to ignore system users (default: UID < 1000)
- **TTY Filtering**: Optional filtering to only log interactive terminal sessions
- **Process Filtering**: Whitelist/blacklist by process name
- **Network CIDR Filtering**: Ignore traffic to private networks (kernel-level filtering)
- **File Path Filtering**: Ignore /tmp, /proc, /sys by prefix matching
- **Thread Filtering**: Optionally ignore threads, only log main processes
- **Rate Limiting**: Token bucket algorithm (50 burst, 200 events/sec per UID) prevents flooding

### Security & Privacy
- **Sensitive Data Redaction**: Automatically redact passwords, tokens, API keys from command lines
- **Binary Hashing**: Optional SHA256 hashing of executed binaries for integrity monitoring
- **Package Verification**: Check if binaries belong to system packages (dpkg/rpm) with persistent cache
- **Privilege Dropping**: Daemon runs as `nobody` (UID 65534) after BPF load, retains only CAP_SYS_PTRACE for masquerading detection
- **Process Masquerading Detection**: Detects when processes impersonate other programs via prctl() comm name changes
- **Deleted Executable Detection**: Identifies fileless malware and post-exploitation cleanup patterns
- **Hardened systemd**: Full security hardening with seccomp, ProtectSystem, PrivateTmp
- **Config Validation**: Path traversal protection, permission checks, integer overflow prevention
- **Tamper Detection**: Daemon lifecycle events logged to syslog/journald with signal sender info

### Performance & Reliability
- **eBPF/CO-RE**: Compile once, run everywhere (kernel >= 5.8)
- **Low Overhead**: Efficient kernel-space filtering minimizes performance impact
- **Username Resolution**: Cached UID→username lookups (256 entry cache)
- **File Hash Caching**: LRU cache (1000 entries) for binary hashes
- **Package Cache**: Persistent disk cache (10k entries) for package lookups
- **Log Rotation**: Built-in rotation (100MB, 10 files) or external logrotate support
- **Config Reload**: SIGHUP support for live config updates without restart

## Architecture

LinMon consists of two main components:

1. **eBPF Programs** (`bpf/`): Kernel-space programs that attach to various kernel tracepoints and kprobes to capture events
2. **Userspace Daemon** (`src/`): Service that loads eBPF programs, collects events, and writes structured logs

### Core vs Optional Features

**LinMon core has zero runtime dependencies** - it works completely standalone after installation. All monitoring features (process, network, file, privilege escalation, security events) require only:
- Linux kernel >= 5.8 with BTF support (standard on Ubuntu 24.04, RHEL 9+)
- Standard C library (glibc/musl)
- No external packages, agents, or services

**Optional enhancements** are available in the `extras/` directory:
- **LKRG integration** - Rootkit prevention and kernel integrity checking (requires `lkrg-dkms` package)
- **SIEM integrations** - Vector.dev, Filebeat, ClickHouse configurations for multi-host deployments
- **Remote syslog** - Tamper-resistant audit trail forwarding

See **[extras/README.md](extras/README.md)** for optional feature documentation.

## Installation

### Pre-built Binaries (Recommended)

Download the latest release for your distribution:

**Ubuntu 24.04**:
```bash
# Download latest release
wget https://github.com/espegro/linmon/releases/latest/download/linmond-ubuntu-24.04-amd64.tar.gz

# Extract
tar -xzf linmond-ubuntu-24.04-amd64.tar.gz

# Install (requires root)
cd linmond-ubuntu-24.04-amd64
sudo cp linmond /usr/local/sbin/
sudo cp linmond.service /etc/systemd/system/
sudo cp linmond.logrotate /etc/logrotate.d/linmond
sudo mkdir -p /etc/linmon /var/log/linmon
sudo cp linmon.conf.example /etc/linmon/linmon.conf

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now linmond

# Verify
sudo systemctl status linmond
```

**RHEL 9 / Rocky Linux 9**:
```bash
# Download latest release
wget https://github.com/espegro/linmon/releases/latest/download/linmond-rhel9-x86_64.tar.gz

# Extract and install (same steps as Ubuntu)
tar -xzf linmond-rhel9-x86_64.tar.gz
cd linmond-rhel9-x86_64
# ... (same installation steps as above)

# IMPORTANT: If SELinux is enabled, fix contexts
sudo restorecon -Rv /usr/local/sbin/linmond /var/log/linmon /var/cache/linmon
```

> **Note**: On RHEL/Rocky with SELinux enabled, the binary needs correct SELinux contexts. The installer handles this automatically, but if you encounter issues, see **[INSTALL.md](INSTALL.md)** SELinux section.

### Build from Source

**Quick Start**:
```bash
# Install dependencies (Ubuntu)
sudo apt-get install -y clang llvm libbpf-dev libelf-dev \
    zlib1g-dev libssl-dev libcap-dev linux-tools-generic

# Build and install
make
sudo ./install.sh
```

For detailed installation instructions including RHEL/Rocky setup, manual installation, and troubleshooting, see **[INSTALL.md](INSTALL.md)**.

## Requirements

### Runtime Requirements (Deployed Binary)
- Linux kernel >= 5.8 (with BTF support)
  - Ubuntu 24.04: ✅ kernel 6.8+
  - RHEL 9: ✅ kernel 5.14+
  - RHEL 10: ✅ kernel 6.x+
- **No external packages required** - LinMon works standalone after installation

### Build Dependencies (Compile from Source)

The following packages are only needed if building from source. Pre-built binaries have no runtime dependencies beyond the kernel.

See **[INSTALL.md](INSTALL.md)** for complete dependency lists for Ubuntu and RHEL.

## Configuration

Create `/etc/linmon/linmon.conf` from the example:

```bash
sudo mkdir -p /etc/linmon
sudo cp linmon.conf.example /etc/linmon/linmon.conf
sudo vi /etc/linmon/linmon.conf
```

Key configuration options:
- `min_uid=1000` - Only log users with UID >= 1000 (ignore system users)
- `max_uid=0` - Maximum UID to log (0 = no limit)
- `monitor_vsock=false` - Monitor vsock (VM/container communication) - disabled by default
- `capture_cmdline=true` - Capture full command-line arguments
- `redact_sensitive=true` - Redact passwords/tokens from command lines
- `hash_binaries=true` - Add SHA256 hash of executed binaries
- `verify_packages=false` - Check if binaries belong to system packages (dpkg/rpm)
- `ignore_processes=` - Comma-separated blacklist (e.g., `systemd,cron`)
- `only_processes=` - Comma-separated whitelist (empty = log all)
- `log_rotate=true` - Built-in log rotation (disable for external logrotate)
- `log_rotate_size=100M` - Max file size before rotation (K/M/G suffixes)
- `log_rotate_count=10` - Number of rotated files to keep
- `log_to_syslog=false` - Also log all events to syslog/journald (for SIEM integration)

## Logs

Events are logged to `/var/log/linmon/events.json` in JSON Lines format (one JSON object per line).

### Example Log Output

#### Process Execution (Interactive Shell)
```json
{
  "timestamp": "2024-12-22T14:30:15.123Z",
  "hostname": "webserver01",
  "type": "process_exec",
  "pid": 12345,
  "ppid": 1000,
  "sid": 1000,
  "pgid": 12345,
  "uid": 1000,
  "username": "alice",
  "tty": "pts/0",
  "comm": "git",
  "filename": "/usr/bin/git",
  "process_name": "git",
  "sha256": "abc123...",
  "package": "git",
  "cmdline": "git status"
}
```

#### Process Execution via sudo (with session tracking)
```json
{
  "timestamp": "2024-12-22T14:30:16.456Z",
  "hostname": "webserver01",
  "type": "process_exec",
  "pid": 5678,
  "ppid": 1234,
  "sid": 5678,
  "pgid": 5678,
  "uid": 0,
  "username": "root",
  "sudo_uid": 1000,
  "sudo_user": "alice",
  "tty": "",
  "comm": "systemctl",
  "filename": "/usr/bin/systemctl",
  "process_name": "systemctl",
  "sha256": "def456...",
  "cmdline": "systemctl restart nginx"
}
```

> **Note**: `sudo_uid` and `sudo_user` fields are automatically added when a process is running via sudo, enabling you to track user activity across privilege escalation.

#### Network Connection (TCP)
```json
{
  "timestamp": "2024-12-22T14:30:17.789Z",
  "hostname": "webserver01",
  "type": "net_connect_tcp",
  "pid": 12346,
  "uid": 1000,
  "username": "alice",
  "comm": "curl",
  "family": 2,
  "protocol": 6,
  "saddr": "192.168.1.100",
  "daddr": "142.250.74.110",
  "sport": 54321,
  "dport": 443
}
```

#### vsock Connection (VM/Container Communication)
```json
{
  "timestamp": "2024-12-28T19:15:42.123Z",
  "hostname": "vmhost01",
  "type": "net_vsock_connect",
  "pid": 5432,
  "ppid": 1234,
  "sid": 5432,
  "pgid": 5432,
  "uid": 1000,
  "username": "alice",
  "tty": "",
  "comm": "vm_app",
  "process_name": "vm_application",
  "saddr": "3",
  "daddr": "2",
  "sport": 12345,
  "dport": 2049,
  "family": 40
}
```

> **Note**: vsock (Virtual Socket) events use CIDs (Context IDs) instead of IP addresses. CID 2 is typically the host, CID 3+ are VMs/containers. This example shows a VM (CID 3) connecting to the host (CID 2) on port 2049. Enable with `monitor_vsock=true` in config.

#### Privilege Escalation (sudo)
```json
{
  "timestamp": "2024-12-22T14:30:18.012Z",
  "hostname": "webserver01",
  "type": "priv_sudo",
  "pid": 12347,
  "old_uid": 1000,
  "new_uid": 0,
  "comm": "sudo",
  "target_comm": "/usr/bin/apt"
}
```

#### Security Event - Bind Shell Detection (T1571)
```json
{
  "timestamp": "2024-12-22T14:30:19.345Z",
  "hostname": "webserver01",
  "type": "security_bind",
  "pid": 9999,
  "uid": 1000,
  "username": "attacker",
  "comm": "nc",
  "port": 4444,
  "family": 2,
  "fd": 3
}
```

#### Security Event - Container Escape (T1611)
```json
{
  "timestamp": "2024-12-22T14:30:20.678Z",
  "hostname": "webserver01",
  "type": "security_unshare",
  "pid": 8888,
  "uid": 1000,
  "username": "user",
  "comm": "unshare",
  "unshare_flags": 268435456
}
```

#### Security Event - Fileless Malware (T1620)
```json
{
  "timestamp": "2024-12-22T14:30:21.901Z",
  "hostname": "webserver01",
  "type": "security_memfd_create",
  "pid": 7777,
  "uid": 1000,
  "username": "user",
  "comm": "python3",
  "memfd_name": "jit-code",
  "memfd_flags": 1
}
```

#### Daemon Shutdown (Tamper Detection)
```json
{
  "timestamp": "2024-12-22T14:30:22.123Z",
  "type": "daemon_shutdown",
  "signal": "SIGTERM",
  "signal_num": 15,
  "sender_pid": 1234,
  "sender_uid": 0,
  "message": "LinMon terminated by signal"
}
```

### Key Fields

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 timestamp with millisecond precision (UTC) |
| `hostname` | Hostname of the system that generated the event (for multi-host SIEM) |
| `type` | Event type (e.g., `process_exec`, `net_connect_tcp`, `security_ptrace`) |
| `sid` | Session ID - groups all processes from same login session |
| `pgid` | Process Group ID - for job control (pipes, etc.) |
| `tty` | Terminal name (e.g., "pts/0") - empty for background processes |
| `username` | Resolved username (requires `resolve_usernames = true`) |
| `comm` | Process name from kernel (max 16 chars, can be modified by process) |
| `filename` | Full path to executable (e.g., `/usr/bin/google-chrome-stable`) - only in process_exec events |
| `process_name` | Basename of executable (e.g., `google-chrome-stable`) - always present in process_exec, best-effort in other events* |

\* **Note on `process_name` availability**: This field is always present in `process_exec` events (from eBPF). For network, privilege, and security events, LinMon uses `readlink()` on `/proc/<pid>/exe` symlink to get the actual executable path. This may fail if:
- `/proc` is mounted with `hidepid` option (restricts visibility of other users' processes)
- The process has already terminated when the event is logged
- SELinux/AppArmor policies block `/proc` access

In these cases, the `process_name` field will be omitted from the JSON event (the event is still logged with `comm` field).

### Filtering Interactive vs Background

```bash
# Only interactive commands (with TTY)
jq 'select(.tty != "")' /var/log/linmon/events.json

# Only background processes (no TTY)
jq 'select(.tty == "")' /var/log/linmon/events.json

# All activity from one SSH session
jq 'select(.sid == 1000)' /var/log/linmon/events.json
```

### Event Types

**Core Monitoring:**
- `process_exec`, `process_exit` - Process execution and termination
- `net_connect_tcp`, `net_accept_tcp` - TCP connections
- `net_send_udp` - UDP traffic
- `net_vsock_connect` - vsock (VM/container) communication
- `file_create`, `file_delete`, `file_modify` - File operations
- `priv_setuid`, `priv_setgid`, `priv_sudo` - Privilege escalation

**Security Monitoring (MITRE ATT&CK):**
- `security_cred_read` - T1003.008, T1552.004 Credential File Access (shadow, sudoers, ssh keys, pam)
- `security_cred_write` - T1098.001, T1098.004 Account Manipulation (shadow, sudoers, ssh backdoors)
- `security_log_tamper` - T1070.001 Log Clearing / Anti-Forensics (truncate, delete /var/log/*)
- `security_persistence` - T1053, T1547 Persistence (cron, systemd, shell profiles, init scripts)
- `security_suid` - T1548.001 SUID/SGID Manipulation (chmod +s)
- `security_ldpreload` - T1574.006 LD_PRELOAD Hijacking
- `security_ptrace` - T1055 Process Injection
- `security_module_load` - T1547.006 Kernel Module Loading
- `security_memfd_create` - T1620 Fileless Malware
- `security_bind` - T1571 Bind Shell / C2 Server
- `security_unshare` - T1611 Container Escape
- `security_execveat` - T1620 Fileless Execution
- `security_bpf` - T1014 eBPF Rootkit

**Daemon Lifecycle (Tamper Detection):**
- `daemon_start` - LinMon monitoring started
- `daemon_reload` - Configuration reload (SIGHUP) with sender PID/UID
- `daemon_shutdown` - Daemon terminated with signal and sender PID/UID

**Log Rotation**: LinMon includes built-in log rotation that is **on by default**:
- Rotates when file reaches 100MB (configurable via `log_rotate_size`)
- Keeps 10 rotated files (configurable via `log_rotate_count`)
- Pattern: `events.json` → `events.json.1` → `events.json.2` → ...
- Disable with `log_rotate = false` to use external logrotate instead
- When disabled, LinMon still handles SIGHUP for log file reopening

## Monitoring & Analysis

### Quick Start Queries

```bash
# View last 10 events
tail -10 /var/log/linmon/events.json | jq

# Follow events in real-time
tail -f /var/log/linmon/events.json | jq

# Find all sudo usage
grep '"type":"priv_sudo"' /var/log/linmon/events.json | jq

# Show process executions by user
grep '"type":"process_exec"' /var/log/linmon/events.json | \
  jq -r '[.timestamp, .username, .cmdline] | @tsv' | column -t

# Detect suspicious network connections
grep '"type":"net_connect_tcp"' /var/log/linmon/events.json | \
  jq 'select(.dport != 80 and .dport != 443 and .dport != 22)'
```

### Integration with Monitoring Systems

LinMon integrates with SIEM and log aggregation platforms for multi-host deployments. All events include a `hostname` field for aggregating logs across multiple systems.

**Ready-to-use integrations** (see `extras/` directory):
- **Vector.dev + ClickHouse** (recommended): High-performance data pipeline with columnar OLAP storage
- **Filebeat + Elasticsearch**: ELK stack integration with full **ECS (Elastic Common Schema)** support
- **Vector.dev + Elasticsearch**: High-performance alternative to Filebeat
- **Splunk HEC**: Commercial SIEM integration (coming soon)

**Quick Start - Vector.dev + ClickHouse**:
```bash
# Install Vector and ClickHouse
curl -sSfL https://sh.vector.dev | bash -s -- -y
sudo apt-get install clickhouse-server clickhouse-client

# Create database schema
clickhouse-client < extras/clickhouse/schema.sql

# Start Vector pipeline
vector --config extras/vector/vector.toml
```

See **[extras/README.md](extras/README.md)** for:
- Complete integration setup guides
- ClickHouse schema and example queries
- Vector.dev and Filebeat configurations
- Performance comparison of different stacks

See **[MONITORING.md](MONITORING.md)** for:
- Complete query examples
- Security detection patterns
- Alerting examples (email, Slack, systemd)
- Performance monitoring
- Troubleshooting guide

## Operational Tasks

### Health Check
```bash
# Check daemon status
sudo systemctl status linmond

# View recent logs
sudo journalctl -u linmond -n 50

# Verify events are being logged
tail -5 /var/log/linmon/events.json
```

### Tamper Detection (Syslog/Journal)

LinMon logs daemon lifecycle events to both JSON log and syslog/journald. This provides tamper detection - even if an attacker deletes the JSON log, the journal entries remain.

```bash
# View daemon lifecycle events
sudo journalctl -t linmond --since "1 hour ago"

# Example output:
# linmond[1234]: daemon_start: version=1.2.2 daemon_sha256=abc123... config_sha256=def456... - LinMon monitoring started
# linmond[1234]: checkpoint: version=1.2.2 seq=12345 events=12345 uptime=1800 daemon_sha256=abc123... config_sha256=def456...
# linmond[1234]: daemon_reload: signal=1 sender_pid=5678 sender_uid=0 version=1.2.2 daemon_sha256=abc123... config_sha256=789abc... - Configuration reload requested
# linmond[1234]: daemon_shutdown: signal=15 sender_pid=9012 sender_uid=0 version=1.2.2 daemon_sha256=abc123... config_sha256=def456... - LinMon terminated by signal

# Check who stopped LinMon (signal sender info)
sudo journalctl -t linmond | grep daemon_shutdown
```

Daemon events include:
- **Signal number**: SIGTERM (15), SIGINT (2), SIGHUP (1)
- **Sender PID**: Which process sent the signal
- **Sender UID**: Which user sent the signal (0 = root)
- **Version**: LinMon daemon version
- **daemon_sha256**: SHA256 hash of linmond binary (detects binary replacement)
- **config_sha256**: SHA256 hash of config file (detects unauthorized config changes)

Periodic checkpoints (default: every 30 minutes) include:
- **seq**: Current sequence number (gaps indicate deleted events)
- **events**: Total event count (mismatch with JSON log = deleted events)
- **uptime**: Daemon uptime in seconds (gaps in checkpoints = daemon interruptions)

#### Remote Syslog Forwarding

For enhanced security, configure remote syslog forwarding so journal entries are stored off-host:

```bash
# Copy the example configuration
sudo cp extras/rsyslog-remote.conf /etc/rsyslog.d/10-linmon-remote.conf

# Edit to set your remote syslog server
sudo vi /etc/rsyslog.d/10-linmon-remote.conf
# Replace: @@remote-syslog-server.example.com:514
# With your actual server and port

# Restart rsyslog
sudo systemctl restart rsyslog
```

See **[extras/rsyslog-remote.conf](extras/rsyslog-remote.conf)** for:
- Complete configuration examples (TCP, UDP, TLS)
- Tamper detection strategies
- Example queries for integrity verification
- Security hardening recommendations

### Full Syslog Integration

To log **all** events to syslog (in addition to the JSON file), enable `log_to_syslog`:

```bash
# Edit config
sudo vi /etc/linmon/linmon.conf
# Set: log_to_syslog = true

# Reload config
sudo systemctl reload linmond

# View all events in journald
sudo journalctl -t linmond -f
```

When enabled, all events (process, network, file, privilege, security) are logged to syslog with priority INFO or WARNING. This is useful for:
- **Central log management**: Forward to remote syslog server
- **SIEM integration**: Ingest events into Splunk, Elasticsearch, etc.
- **Audit compliance**: Meet regulatory requirements for log retention

**Note**: This can generate significant syslog volume on busy systems.

### Reload Configuration
```bash
# After editing /etc/linmon/linmon.conf
sudo systemctl reload linmond

# Or send SIGHUP directly
sudo pkill -HUP linmond
```

### Troubleshooting

**No events logged**:
```bash
# Check UID filtering
id  # Your UID should be >= min_uid in config
grep min_uid /etc/linmon/linmon.conf

# Test with known activity
ls /tmp
grep "$(whoami)" /var/log/linmon/events.json | tail -5
```

**Too many events**:
```bash
# Find noisy processes
jq -r '.comm' /var/log/linmon/events.json | sort | uniq -c | sort -rn | head -20

# Add to ignore_processes in config
sudo vi /etc/linmon/linmon.conf  # Add: ignore_processes = chrome,firefox
sudo systemctl reload linmond
```

See **[MONITORING.md](MONITORING.md)** for complete troubleshooting guide.

## Documentation

### Core Documentation
- **[README.md](README.md)** - This file: overview, quick start, configuration
- **[INSTALL.md](INSTALL.md)** - Installation guide: dependencies, build, troubleshooting
- **[MONITORING.md](MONITORING.md)** - Monitoring guide: queries, alerts, integrations
- **[SECURITY.md](SECURITY.md)** - Security features and hardening details
- **[CLAUDE.md](CLAUDE.md)** - Development guide: architecture, building, contributing

### Optional Features
- **[extras/README.md](extras/README.md)** - Optional integrations: LKRG, SIEM, remote syslog
- **[extras/lkrg/README.md](extras/lkrg/README.md)** - Rootkit prevention with LKRG (optional)

## Development

See **[CLAUDE.md](CLAUDE.md)** for:
- Detailed architecture documentation
- Build system internals
- Adding new event types
- eBPF development guidelines
- Code style and security considerations
