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
- **Log Rotation**: Automatic rotation with logrotate (30 days, 100MB limit)
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

## Logs

Events are logged to `/var/log/linmon/events.json` in JSON Lines format (one JSON object per line):

```json
{"timestamp":"2024-11-30T10:15:30.123Z","type":"process_exec","pid":12345,"ppid":1234,"uid":1000,"username":"alice","comm":"bash","filename":"/usr/bin/bash","cmdline":"/bin/bash -c ls","sha256":"abc123..."}
{"timestamp":"2024-11-30T10:15:31.456Z","type":"net_connect_tcp","pid":12346,"uid":1000,"username":"alice","comm":"curl","saddr":"192.168.1.100","daddr":"1.1.1.1","sport":54321,"dport":443}
```

**Event Types**:
- `process_exec`, `process_exit` - Process execution and termination
- `net_connect_tcp`, `net_accept_tcp` - TCP connections
- `net_send_udp` - UDP traffic
- `file_open`, `file_create`, `file_delete`, `file_modify` - File operations
- `priv_setuid`, `priv_setgid`, `priv_sudo` - Privilege escalation

**Log Rotation**: Automatic rotation via logrotate:
- Rotates daily or at 100MB
- Keeps 30 days of compressed logs
- Maintains proper permissions (0640 nobody:nogroup)

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
