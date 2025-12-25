# LinMon Installation Guide

This guide explains how to build and install LinMon from source. It covers dependencies, build process, installation steps, and system configuration.

## Table of Contents
- [System Requirements](#system-requirements)
- [Dependencies](#dependencies)
- [Building from Source](#building-from-source)
- [Installation Methods](#installation-methods)
- [Post-Installation](#post-installation)
- [Uninstallation](#uninstallation)
- [Troubleshooting](#troubleshooting)

## System Requirements

### Kernel Requirements
LinMon requires a modern Linux kernel with eBPF/CO-RE support:

- **Minimum**: Linux 5.8
- **Recommended**: Linux 5.14+ (RHEL 9) or 6.8+ (Ubuntu 24.04)
- **Required kernel features**:
  - `CONFIG_DEBUG_INFO_BTF=y` (BTF support for CO-RE)
  - `CONFIG_BPF=y` and `CONFIG_BPF_SYSCALL=y`
  - `CONFIG_BPF_JIT=y` (for performance)

**Verify BTF support**:
```bash
ls -l /sys/kernel/btf/vmlinux
# Should show a file. If missing, your kernel lacks BTF support.
```

### Supported Distributions
| Distribution | Kernel | Status | Notes |
|--------------|--------|--------|-------|
| Ubuntu 24.04 | 6.8+ | ✅ Fully supported | All features work |
| Ubuntu 22.04 | 5.15+ | ✅ Fully supported | All features work |
| RHEL 9 / Rocky 9 / AlmaLinux 9 | 5.14+ | ✅ Fully supported | Some syscall tracepoints may fall back to kprobes |
| RHEL 10 / Rocky 10 | 6.x+ | ✅ Expected to work | Newer kernel, full support expected |
| Debian 12+ | 6.1+ | ✅ Should work | Similar to Ubuntu |

## Dependencies

### Ubuntu / Debian

**Install all build dependencies**:
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
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
```

**Package breakdown**:
- `clang`, `llvm`: eBPF bytecode compilation
- `gcc`, `make`: Userspace daemon compilation
- `linux-tools-generic`: Provides `bpftool` for skeleton generation
- `libbpf-dev`: BPF loading and CO-RE support
- `libelf-dev`: ELF file parsing
- `zlib1g-dev`: Compression support
- `libssl-dev`: SHA256 hashing (binary integrity)
- `libcap-dev`: Capability management (privilege dropping)
- `linux-headers-$(uname -r)`: Kernel headers for BTF

### RHEL / Rocky Linux / AlmaLinux

**Enable CodeReady Builder (CRB) repository**:
```bash
# RHEL 9:
sudo subscription-manager repos --enable codeready-builder-for-rhel-9-$(arch)-rpms

# RHEL 10:
sudo subscription-manager repos --enable codeready-builder-for-rhel-10-$(arch)-rpms

# Rocky/AlmaLinux 9+:
sudo dnf config-manager --set-enabled crb

# Rocky 8 (if applicable):
sudo dnf config-manager --set-enabled powertools
```

**Install all build dependencies**:
```bash
sudo dnf install -y \
    gcc \
    make \
    clang \
    llvm \
    bpftool \
    libbpf-devel \
    elfutils-libelf-devel \
    zlib-devel \
    openssl-devel \
    libcap-devel \
    kernel-devel
```

**Package breakdown**:
- `clang`, `llvm`: eBPF bytecode compilation
- `gcc`, `make`: Userspace daemon compilation
- `bpftool`: Skeleton generation (different package than Ubuntu)
- `libbpf-devel`: BPF loading and CO-RE support
- `elfutils-libelf-devel`: ELF file parsing
- `zlib-devel`: Compression support
- `openssl-devel`: SHA256 hashing
- `libcap-devel`: Capability management
- `kernel-devel`: Kernel headers for BTF

## Building from Source

### Download Source

**Option 1: Git clone**:
```bash
git clone https://github.com/espegro/linmon.git
cd linmon
```

**Option 2: Release tarball**:
```bash
# Download latest release (replace VERSION with actual version, e.g., v1.1.0)
VERSION=v1.1.0
curl -L -O https://github.com/espegro/linmon/archive/refs/tags/${VERSION}.tar.gz
tar xzf ${VERSION}.tar.gz
cd linmon-${VERSION#v}
```

### Build

```bash
make
```

**What happens during build**:

1. **eBPF compilation** (`bpf/*.bpf.c` → `build/bpf/*.bpf.o`):
   - Compiled with `clang -target bpf`
   - Debug symbols stripped with `llvm-strip`
   - Creates BPF bytecode

2. **Skeleton generation** (`.bpf.o` → `src/*.skel.h`):
   - Uses `bpftool gen skeleton`
   - Creates C headers with BPF loading boilerplate
   - Auto-detects `bpftool` location (Ubuntu vs RHEL)

3. **Userspace compilation** (`src/*.c` → `build/linmond`):
   - Compiles daemon with `gcc`
   - Links against libbpf, libelf, zlib, pthread, libcrypto, libcap

**Verify build**:
```bash
./build/linmond --version
# Should output: LinMon version X.Y.Z (matching VERSION file)
```

### Build Troubleshooting

**Error: "bpftool not found"**:
- Ubuntu: `sudo apt-get install linux-tools-generic`
- RHEL: `sudo dnf install bpftool`

**Error: "vmlinux.h not found" or BTF errors**:
```bash
# Check BTF support
ls /sys/kernel/btf/vmlinux
# If missing, upgrade kernel or use a distribution with BTF enabled
```

**Error: "libbpf not found"**:
- Ubuntu: `sudo apt-get install libbpf-dev`
- RHEL: `sudo dnf install libbpf-devel` (may need CRB repo)

## Installation Methods

### Method 1: Automated Installation (Recommended)

Use the provided installation script with security checks:

```bash
sudo ./install.sh
```

**What `install.sh` does**:

1. **Detects distribution**:
   - Auto-detects `nogroup` (Ubuntu) vs `nobody` (RHEL) group

2. **Creates directories**:
   - `/var/log/linmon` - Log directory (owner: `nobody:nogroup`, mode: `0750`)
   - `/var/cache/linmon` - Cache directory (owner: `nobody:nogroup`, mode: `0750`)
   - `/etc/linmon` - Config directory (owner: `root:root`)

3. **Installs files**:
   - `/usr/local/sbin/linmond` - Binary (mode: `0755`)
   - `/etc/linmon/linmon.conf` - Config (mode: `0600`, only if doesn't exist)
   - `/etc/systemd/system/linmond.service` - Systemd unit
   - `/etc/logrotate.d/linmond` - Logrotate config

4. **Security verification**:
   - Checks config file permissions (must be `0600`)
   - Checks config owner (must be `root:root`)
   - Warns about world-writable config

5. **Optional post-install**:
   - Prompts to enable systemd service
   - Prompts to start service

### Method 2: Makefile Installation

```bash
sudo make install
```

**What `make install` does**:
- Same as `install.sh` but without interactive prompts
- Creates all directories with proper permissions
- Installs binary, config, systemd service, logrotate
- Auto-detects `nogroup` vs `nobody` group
- Runs `systemctl daemon-reload`

**Note**: Does NOT start or enable the service automatically.

### Method 3: Manual Installation

For advanced users who want full control:

#### 1. Install Binary
```bash
sudo install -D -m 755 build/linmond /usr/local/sbin/linmond
```

#### 2. Create Directories
```bash
sudo mkdir -p /var/log/linmon
sudo mkdir -p /var/cache/linmon
sudo mkdir -p /etc/linmon

# Ubuntu/Debian:
sudo chown nobody:nogroup /var/log/linmon /var/cache/linmon

# RHEL/Rocky:
sudo chown nobody:nobody /var/log/linmon /var/cache/linmon

# Set permissions
sudo chmod 0750 /var/log/linmon /var/cache/linmon
```

#### 3. Install Configuration
```bash
# Copy example config (only if doesn't exist)
if [ ! -f /etc/linmon/linmon.conf ]; then
    sudo cp linmon.conf.example /etc/linmon/linmon.conf
fi

# Secure config file
sudo chown root:root /etc/linmon/linmon.conf
sudo chmod 0600 /etc/linmon/linmon.conf
```

**Security Note**: Config file MUST be `0600` and owned by `root:root`. The daemon will refuse to start with insecure permissions.

#### 4. Install Systemd Service
```bash
sudo cp linmond.service /etc/systemd/system/
sudo systemctl daemon-reload
```

#### 5. Install Logrotate Config (Optional)
```bash
# Ubuntu/Debian:
sudo sed 's/nobody nogroup/nobody nogroup/' linmond.logrotate > /etc/logrotate.d/linmond

# RHEL/Rocky:
sudo sed 's/nobody nogroup/nobody nobody/' linmond.logrotate > /etc/logrotate.d/linmond

sudo chmod 0644 /etc/logrotate.d/linmond
```

#### 6. SELinux Policy (RHEL/Rocky only)
```bash
cd selinux
sudo ./install-selinux.sh
```

**What this does**:
- Compiles and installs SELinux policy module
- Allows `linmond` to use eBPF for system monitoring
- Required for SELinux enforcing mode

**Check for denials**:
```bash
ausearch -m avc -ts recent | grep linmond
```

## Post-Installation

### 1. Configure LinMon

Edit `/etc/linmon/linmon.conf`:
```bash
sudo vi /etc/linmon/linmon.conf
```

**Key settings to review**:
```ini
# Monitor all users or only interactive users?
min_uid = 0          # 0 = all users, 1000 = only human users

# Capture command-line arguments?
capture_cmdline = true

# Hash binaries for integrity monitoring?
hash_binaries = true

# Verify package ownership (requires dpkg/rpm)?
verify_packages = false

# Built-in log rotation?
log_rotate = true
log_rotate_size = 100M
log_rotate_count = 10
```

See `linmon.conf.example` for all options with detailed explanations.

### 2. Enable and Start Service

```bash
# Enable service to start on boot
sudo systemctl enable linmond

# Start service now
sudo systemctl start linmond

# Check status
sudo systemctl status linmond
```

### 3. Verify Installation

**Check daemon is running**:
```bash
sudo systemctl status linmond
# Should show "active (running)"
```

**Check BPF programs are loaded**:
```bash
sudo bpftool prog list | grep linmon
# Should show multiple BPF programs
```

**Generate test activity and check logs**:
```bash
# Generate some activity
ls /tmp
ps aux | head

# Check logs (wait a few seconds)
sudo tail -10 /var/log/linmon/events.json

# Or follow in real-time with jq
sudo tail -f /var/log/linmon/events.json | jq
```

**Check systemd logs for errors**:
```bash
sudo journalctl -u linmond -n 50 --no-pager
```

### 4. Test Log Rotation (if enabled)

If using built-in rotation (`log_rotate = true`):
```bash
# Monitor rotation (happens when file reaches log_rotate_size)
ls -lh /var/log/linmon/
```

If using external logrotate:
```bash
# Test logrotate config
sudo logrotate -d /etc/logrotate.d/linmond

# Force rotation
sudo logrotate -f /etc/logrotate.d/linmond

# Verify linmond reopened log
sudo journalctl -u linmond | grep "reopened"
```

### 5. Reload Configuration

To reload config without restarting:
```bash
# Edit config
sudo vi /etc/linmon/linmon.conf

# Reload (sends SIGHUP to daemon)
sudo systemctl reload linmond

# Verify reload
sudo journalctl -u linmond | tail -5
```

## Uninstallation

### Method 1: Using Makefile

```bash
sudo make uninstall
```

**What this does**:
- Stops and disables systemd service
- Removes binary (`/usr/local/sbin/linmond`)
- Removes systemd service file
- Removes logrotate config
- Runs `systemctl daemon-reload`

**Note**: Does NOT remove logs, cache, or config. Remove manually if needed:
```bash
sudo rm -rf /var/log/linmon
sudo rm -rf /var/cache/linmon
sudo rm -rf /etc/linmon
```

### Method 2: Manual Uninstallation

```bash
# Stop and disable service
sudo systemctl stop linmond
sudo systemctl disable linmond

# Remove files
sudo rm /usr/local/sbin/linmond
sudo rm /etc/systemd/system/linmond.service
sudo rm /etc/logrotate.d/linmond

# Reload systemd
sudo systemctl daemon-reload

# Optional: Remove data directories
sudo rm -rf /var/log/linmon
sudo rm -rf /var/cache/linmon
sudo rm -rf /etc/linmon
```

### SELinux Cleanup (RHEL/Rocky)

If you installed the SELinux policy:
```bash
sudo semodule -r linmond
```

## Troubleshooting

### Build Issues

**Problem**: `make` fails with "bpftool not found"

**Solution**:
```bash
# Ubuntu
sudo apt-get install linux-tools-generic
which bpftool  # Should show /usr/lib/linux-tools/.../bpftool

# RHEL/Rocky
sudo dnf install bpftool
which bpftool  # Should show /usr/sbin/bpftool or /usr/bin/bpftool
```

**Problem**: "BTF: .tmp_vmlinux.btf: pahole (pahole) is not available"

**Solution**: Your kernel doesn't have BTF support. Upgrade to a newer kernel or use a distribution with BTF enabled (Ubuntu 20.04+, RHEL 9+).

**Problem**: `libbpf` not found

**Solution**:
```bash
# Ubuntu
sudo apt-get install libbpf-dev

# RHEL/Rocky (may need CRB repo)
sudo dnf config-manager --set-enabled crb
sudo dnf install libbpf-devel
```

### Runtime Issues

**Problem**: Daemon fails to start with "Permission denied"

**Solution**: Check if you're running as root:
```bash
sudo systemctl start linmond
```

**Problem**: "Failed to increase RLIMIT_MEMLOCK"

**Solution**: This requires root/CAP_SYS_RESOURCE. Make sure systemd service has:
```ini
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE
```

**Problem**: No events logged

**Solutions**:
1. Check UID filtering:
   ```bash
   id  # Your UID should be >= min_uid in config
   grep min_uid /etc/linmon/linmon.conf
   ```

2. Check monitoring is enabled:
   ```bash
   grep "monitor_processes\|monitor_tcp" /etc/linmon/linmon.conf
   ```

3. Generate test activity:
   ```bash
   ls /tmp
   sleep 1
   sudo tail /var/log/linmon/events.json
   ```

**Problem**: SELinux denials (RHEL/Rocky)

**Solution**:
```bash
# Check for denials
ausearch -m avc -ts recent | grep linmond

# Install SELinux policy
cd selinux
sudo ./install-selinux.sh

# If still denied, generate custom policy
ausearch -m avc -ts recent | audit2allow -M linmond_extra
sudo semodule -i linmond_extra.pp
```

### Performance Issues

**Problem**: High CPU usage

**Solutions**:
1. Check event rate:
   ```bash
   sudo tail -f /var/log/linmon/events.json | pv -l -i 1 > /dev/null
   ```

2. Reduce noise with filters:
   ```bash
   sudo vi /etc/linmon/linmon.conf
   # Add: ignore_processes = chrome,firefox,systemd
   # Or: min_uid = 1000  # Ignore system users
   sudo systemctl reload linmond
   ```

3. Disable expensive features:
   ```bash
   # In config:
   hash_binaries = false
   verify_packages = false
   ```

**Problem**: Large log files

**Solutions**:
1. Enable log rotation:
   ```bash
   log_rotate = true
   log_rotate_size = 50M
   log_rotate_count = 5
   ```

2. Add more aggressive filters:
   ```bash
   ignore_processes = browser,editor,ide
   ignore_file_paths = /tmp/,/proc/,/sys/
   ```

## Additional Resources

- **[README.md](README.md)**: Overview and quick start
- **[MONITORING.md](MONITORING.md)**: Query examples and monitoring guides
- **[SECURITY.md](SECURITY.md)**: Security architecture and hardening
- **[CLAUDE.md](CLAUDE.md)**: Development guide and architecture details
- **[linmon.conf.example](linmon.conf.example)**: Full configuration reference

## Support

For issues and questions:
- GitHub Issues: https://github.com/espegro/linmon/issues
- Check existing documentation above
- Search closed issues for solutions
