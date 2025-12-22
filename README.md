# LinMon - Linux Activity Monitor

LinMon is a system monitoring service for Linux (Ubuntu/RHEL) that logs interactive user activity, similar to Sysmon for Windows. It uses eBPF (Extended Berkeley Packet Filter) to instrument the kernel with minimal overhead.

## Features

### Core Monitoring
- **Process Monitoring**: Track execution and termination with full command-line arguments
- **Network Monitoring**: TCP connections (connect/accept) and UDP traffic with IPv4/IPv6 support
- **File Monitoring**: Track file create, modify, delete operations
- **Privilege Escalation**: Detect setuid, setgid, and sudo usage

### Advanced Filtering
- **UID/GID Filtering**: Configurable to ignore system users (default: UID < 1000)
- **TTY Filtering**: Optional filtering to only log interactive terminal sessions
- **Process Filtering**: Whitelist/blacklist by process name
- **Network CIDR Filtering**: Ignore traffic to private networks (kernel-level filtering)
- **File Path Filtering**: Ignore /tmp, /proc, /sys by prefix matching
- **Thread Filtering**: Optionally ignore threads, only log main processes
- **Rate Limiting**: Token bucket algorithm (20 burst, 100 events/sec per UID) prevents flooding

### Security & Privacy
- **Sensitive Data Redaction**: Automatically redact passwords, tokens, API keys from command lines
- **Binary Hashing**: Optional SHA256 hashing of executed binaries for integrity monitoring
- **Privilege Dropping**: Daemon runs as `nobody` (UID 65534) after BPF load, zero capabilities
- **Hardened systemd**: Full security hardening with seccomp, ProtectSystem, PrivateTmp
- **Config Validation**: Path traversal protection, permission checks, integer overflow prevention

### Performance & Reliability
- **eBPF/CO-RE**: Compile once, run everywhere (kernel >= 5.8)
- **Low Overhead**: Efficient kernel-space filtering minimizes performance impact
- **Username Resolution**: Cached UID→username lookups (256 entry cache)
- **File Hash Caching**: LRU cache (1000 entries) for binary hashes
- **Log Rotation**: Built-in rotation (100MB, 10 files) or external logrotate support
- **Config Reload**: SIGHUP support for live config updates without restart

## Architecture

LinMon consists of two main components:

1. **eBPF Programs** (`bpf/`): Kernel-space programs that attach to various kernel tracepoints and kprobes to capture events
2. **Userspace Daemon** (`src/`): Service that loads eBPF programs, collects events, and writes structured logs

## Requirements

### System Requirements
- Linux kernel >= 5.8 (with BTF support)
  - Ubuntu 24.04: ✅ kernel 6.8+
  - RHEL 9: ✅ kernel 5.14+
  - RHEL 10: ✅ kernel 6.x+

### Build Dependencies
- **eBPF toolchain**:
  - libbpf >= 0.7
  - clang >= 11
  - llvm
  - kernel headers (for BTF/vmlinux.h)
- **C compiler**: gcc or clang
- **Build tools**: make
- **Libraries**:
  - libelf (ELF file handling)
  - zlib (compression)
  - libssl/libcrypto (SHA256 hashing)
  - libcap (capability management)
  - pthread (threading, usually in glibc)

### Ubuntu 24.04 / Debian
```bash
# Install all build dependencies
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    gcc \
    make \
    linux-tools-generic \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    libssl-dev \
    libcap-dev \
    linux-headers-$(uname -r)

# Note: linux-tools-generic provides bpftool on Ubuntu
```

### RHEL 9 / RHEL 10 / Rocky Linux / AlmaLinux
```bash
# Install all build dependencies
sudo dnf install -y \
    clang \
    llvm \
    gcc \
    make \
    bpftool \
    libbpf-devel \
    elfutils-libelf-devel \
    zlib-devel \
    openssl-devel \
    libcap-devel \
    kernel-devel

# RHEL 9/10 note: You may need to enable CodeReady Builder (CRB) for some packages
# RHEL 9:
sudo subscription-manager repos --enable codeready-builder-for-rhel-9-$(arch)-rpms
# RHEL 10:
sudo subscription-manager repos --enable codeready-builder-for-rhel-10-$(arch)-rpms

# For Rocky/Alma (no subscription needed):
sudo dnf config-manager --set-enabled crb  # Rocky 9+
# or
sudo dnf config-manager --set-enabled powertools  # Rocky 8
```

## Building

```bash
make
```

This will:
1. Compile eBPF programs to BPF bytecode
2. Build the userspace daemon
3. Create the `linmond` binary

### Build Verification

After installation, verify the build works:
```bash
# Check kernel BTF support (required for BPF CO-RE)
ls -l /sys/kernel/btf/vmlinux
# Should show a file - if missing, your kernel doesn't have BTF

# Check bpftool availability
bpftool version
# Should show bpftool version

# Test the binary
./build/linmond --version
```

### Platform-Specific Notes

**Ubuntu 24.04**:
- ✅ All dependencies available in main repos
- ✅ BTF enabled by default (kernel 6.8+)
- ✅ libbpf 1.3+ available

**RHEL 9**:
- ✅ Full eBPF support (kernel 5.14+)
- ⚠️ May need CRB repo for libbpf-devel
- ✅ BTF enabled by default
- ⚠️ SELinux policy required (see below)

**RHEL 10** (when released):
- ✅ Expected to have kernel 6.x+
- ✅ Full modern eBPF support

**Rocky Linux / AlmaLinux**:
- ✅ Same as RHEL, but free
- ⚠️ Enable 'crb' or 'powertools' repo
- No subscription needed

## Running

```bash
# Run in foreground (for testing)
sudo ./build/linmond

# Install as systemd service
sudo make install
sudo systemctl enable linmond
sudo systemctl start linmond
```

### SELinux (RHEL 9 / Rocky Linux / AlmaLinux)

On systems with SELinux enforcing, install the SELinux policy module:

```bash
cd selinux
sudo ./install-selinux.sh
```

This allows linmond to use eBPF for system monitoring. If you see SELinux denials:
```bash
# Check for denials
ausearch -m avc -ts recent | grep linmond

# Generate additional policy if needed
ausearch -m avc -ts recent | audit2allow -M linmond_extra
sudo semodule -i linmond_extra.pp
```

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
- `capture_cmdline=true` - Capture full command-line arguments
- `redact_sensitive=true` - Redact passwords/tokens from command lines
- `ignore_processes=` - Comma-separated blacklist (e.g., `systemd,cron`)
- `only_processes=` - Comma-separated whitelist (empty = log all)
- `log_rotate=true` - Built-in log rotation (disable for external logrotate)
- `log_rotate_size=100M` - Max file size before rotation (K/M/G suffixes)
- `log_rotate_count=10` - Number of rotated files to keep

## Logs

Events are logged to `/var/log/linmon/events.json` in JSON Lines format (one JSON object per line).

### Example Log Output

#### Process Execution (Interactive Shell)
```json
{
  "timestamp": "2024-12-22T14:30:15.123Z",
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
  "cmdline": "git status"
}
```

#### Process Execution (Background/Daemon - no TTY)
```json
{
  "timestamp": "2024-12-22T14:30:16.456Z",
  "type": "process_exec",
  "pid": 5678,
  "ppid": 1,
  "sid": 5678,
  "pgid": 5678,
  "uid": 0,
  "username": "root",
  "tty": "",
  "comm": "cron",
  "filename": "/usr/sbin/cron"
}
```

#### Network Connection (TCP)
```json
{
  "timestamp": "2024-12-22T14:30:17.789Z",
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

#### Privilege Escalation (sudo)
```json
{
  "timestamp": "2024-12-22T14:30:18.012Z",
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
  "type": "security_memfd_create",
  "pid": 7777,
  "uid": 1000,
  "username": "user",
  "comm": "python3",
  "memfd_name": "jit-code",
  "memfd_flags": 1
}
```

### Key Fields

| Field | Description |
|-------|-------------|
| `sid` | Session ID - groups all processes from same login session |
| `pgid` | Process Group ID - for job control (pipes, etc.) |
| `tty` | Terminal name (e.g., "pts/0") - empty for background processes |
| `username` | Resolved username (requires `resolve_usernames = true`) |

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
- `file_create`, `file_delete`, `file_modify` - File operations
- `priv_setuid`, `priv_setgid`, `priv_sudo` - Privilege escalation

**Security Monitoring (MITRE ATT&CK):**
- `security_cred_read` - T1003.008 Credential File Access (shadow, sudoers, ssh, pam)
- `security_ldpreload` - T1574.006 LD_PRELOAD Hijacking
- `security_ptrace` - T1055 Process Injection
- `security_module_load` - T1547.006 Kernel Module Loading
- `security_memfd_create` - T1620 Fileless Malware
- `security_bind` - T1571 Bind Shell / C2 Server
- `security_unshare` - T1611 Container Escape
- `security_execveat` - T1620 Fileless Execution
- `security_bpf` - T1014 eBPF Rootkit

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

LinMon integrates with:
- **ELK Stack**: Use Filebeat to ship JSON logs to Elasticsearch
- **Splunk**: Configure as JSON sourcetype for security monitoring
- **Grafana**: Use mtail or similar to export metrics from logs
- **Custom**: Parse JSON with `jq`, `python`, or your preferred tool

See **[MONITORING.md](MONITORING.md)** for:
- Complete query examples
- Security detection patterns
- Integration guides (ELK, Splunk, Grafana)
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

- **[README.md](README.md)** - This file: overview, installation, configuration
- **[MONITORING.md](MONITORING.md)** - Monitoring guide: queries, alerts, integrations
- **[SECURITY.md](SECURITY.md)** - Security features and hardening details
- **[CLAUDE.md](CLAUDE.md)** - Development guide: architecture, building, contributing

## Development

See **[CLAUDE.md](CLAUDE.md)** for:
- Detailed architecture documentation
- Build system internals
- Adding new event types
- eBPF development guidelines
- Code style and security considerations
