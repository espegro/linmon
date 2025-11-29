# LinMon - Linux Activity Monitor

LinMon is a system monitoring service for Linux (Ubuntu/RHEL) that logs interactive user activity, similar to Sysmon for Windows. It uses eBPF (Extended Berkeley Packet Filter) to instrument the kernel with minimal overhead.

## Features

- **Process Monitoring**: Track process execution and termination with full details
- **Interactive User Focus**: Automatically filters to only log activity from users with TTY sessions
- **UID/GID Filtering**: Configurable filtering to ignore system users (UID < 1000 by default)
- **Process Name Filtering**: Whitelist/blacklist specific processes
- **Sensitive Data Redaction**: Automatically redact passwords, tokens, and API keys from command lines
- **Command-line Capture**: Optional full argument capture
- **eBPF/CO-RE**: Portable across kernel versions - compile once, run everywhere (kernel >= 5.8)
- **Low Overhead**: Efficient kernel-space filtering minimizes performance impact

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

Events are logged to:
- `/var/log/linmon/events.json` - JSON-formatted event log with timestamps
- Syslog integration (optional)

**Log Rotation**: LinMon includes a logrotate configuration (`/etc/logrotate.d/linmond`) that:
- Rotates logs daily or when they reach 100MB
- Keeps 30 days of compressed logs
- Maintains proper permissions (0640 nobody:nogroup)

Installed automatically by `make install` or `./install.sh`.

## Development

See `CLAUDE.md` for development guidelines and architecture details.
