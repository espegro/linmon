# LinMon Security Features

LinMon implements defense-in-depth security measures to minimize attack surface.

## Privilege Dropping

LinMon follows a strict privilege dropping sequence:

### 1. UID/GID Dropping (First)
LinMon drops to `nobody` user (UID/GID 65534) after:
- BPF programs are loaded and attached
- Log file is opened
- All privileged operations complete

```c
setgroups(0, NULL);  // Clear ALL supplementary groups (disk, adm, docker, etc.)
setgid(65534);       // Drop to nobody group
setuid(65534);       // Drop to nobody user
```

**Critical**:
- Supplementary groups must be cleared first (prevents retaining privileged group memberships)
- This must happen BEFORE dropping capabilities (requires CAP_SETUID/CAP_SETGID)

### 2. Capability Retention (After UID/GID Drop)
LinMon retains **only CAP_SYS_PTRACE** after privilege drop for masquerading detection:

```c
// Before UID drop:
prepare_capabilities();  // Set CAP_SYS_PTRACE as ambient capability

// After UID/GID drop to nobody:
// Drop CAP_SETUID and CAP_SETGID to prevent regaining root
cap_set_flag(caps, CAP_PERMITTED, 2, {CAP_SETUID, CAP_SETGID}, CAP_CLEAR);
cap_set_flag(caps, CAP_EFFECTIVE, 2, {CAP_SETUID, CAP_SETGID}, CAP_CLEAR);

// Result: nobody user with only CAP_SYS_PTRACE (read /proc/<pid>/exe)
```

**Purpose**: CAP_SYS_PTRACE allows reading `/proc/<pid>/exe` for all users, enabling process masquerading detection.

**Security measures**:
- Ambient capabilities (kernel >= 4.3) preserve CAP_SYS_PTRACE across UID change
- SECBIT_NO_SETUID_FIXUP + SECBIT_KEEP_CAPS prevent capability clearing on setuid()
- Both securebits locked with _LOCKED variants
- CAP_SETUID and CAP_SETGID explicitly dropped after UID transition
- Verification ensures cannot regain root: `setuid(0)` must fail

**Critical**: If capability setup fails, LinMon **aborts** (does not continue with incorrect privileges).

## Configuration Security

### 1. Log File Path Validation
- **Must** be absolute path (starts with `/`)
- **Cannot** contain `..` (path traversal protection)
- Invalid paths are rejected

```ini
log_file = /var/log/linmon/events.json  # OK
log_file = ../../etc/passwd              # REJECTED
log_file = relative/path.log             # REJECTED
```

### 2. Config File Permissions
LinMon validates config file permissions on startup:

**Critical Checks** (abort if failed):
- ❌ World-writable → **ABORT**

**Warnings** (continue with warning):
- ⚠️ Not owned by root
- ⚠️ Group-writable

**Recommended permissions**:
```bash
sudo chown root:root /etc/linmon/linmon.conf
sudo chmod 0600 /etc/linmon/linmon.conf
```

### 3. Integer Overflow Protection
UID parsing uses `strtoul()` instead of `atoi()`:
- Validates input is pure decimal
- Checks for overflow (> UINT_MAX)
- Rejects negative values

## Systemd Hardening

Install with hardened systemd service:

```bash
sudo cp linmond.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now linmond
```

### Systemd Security Features (eBPF-Compatible)

LinMon uses systemd hardening features that are compatible with eBPF requirements:

| Feature | Status | Purpose |
|---------|--------|---------|
| `ProtectSystem=strict` | ✅ Enabled | Read-only root filesystem |
| `ProtectHome=yes` | ✅ Enabled | No access to home directories |
| `ReadWritePaths=...` | ✅ Enabled | Only writable: /var/log/linmon, /var/cache/linmon |
| `PrivateTmp=yes` | ✅ Enabled | Isolated /tmp |
| `ProtectKernelTunables=yes` | ✅ Enabled | No /proc/sys writes |
| `ProtectControlGroups=yes` | ✅ Enabled | No cgroup modifications |
| `RestrictRealtime=yes` | ✅ Enabled | No realtime scheduling |
| `LockPersonality=yes` | ✅ Enabled | No personality changes |
| `RestrictAddressFamilies` | ✅ Enabled | Only Unix/IPv4/IPv6 sockets |
| `SystemCallFilter` | ✅ Enabled | Whitelist of required syscalls (based on strace analysis) |
| `OOMScoreAdjust=-900` | ✅ Enabled | Protected from OOM killer |

### SystemCallFilter Whitelist

Based on strace analysis, LinMon requires the following syscalls:

**Standard Groups**:
- `@system-service` - Basic service operations
- `@file-system` - File I/O operations
- `@io-event` - Event notification (epoll)
- `@network-io` - Network operations
- `@basic-io` - Basic I/O primitives

**eBPF Operations**:
- `bpf` - Load BPF programs and maps
- `perf_event_open` - Attach to kernel tracepoints

**Privilege Management**:
- `setuid`, `setgid` - Drop to nobody user
- `capset`, `capget` - Manage capabilities
- `setrlimit` - Set resource limits

**Event Loop**:
- `epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait` - Event loop operations

**Memory Management**:
- `mmap`, `munmap` - Memory allocation
- `mremap` - Remap memory (needed for large BTF data ~6.7MB)
- `mprotect` - Memory protection

**Process Control**:
- `prctl` - Process control operations
- `prlimit64` - Resource limit management
- `getrandom` - Random number generation
- `uname` - System information

**Signal/Thread Setup**:
- `rt_sigaction`, `rt_sigreturn` - Signal handling
- `set_tid_address`, `set_robust_list` - Thread setup
- `rseq` - Restartable sequences
- `arch_prctl` - Architecture-specific process control

**eBPF-incompatible features** (disabled with rationale):

| Feature | Reason Disabled |
|---------|----------------|
| `NoNewPrivileges=yes` | ❌ Conflicts with eBPF loading (needs CAP_SYS_ADMIN) |
| `MemoryDenyWriteExecute=yes` | ❌ eBPF JIT compilation requires RWX memory |
| `ProtectKernelModules=yes` | ❌ eBPF loading accesses kernel interfaces |
| `RestrictNamespaces=yes` | ❌ May interfere with BPF map operations |
| `RestrictSUIDSGID=yes` | ❌ LinMon calls setuid/setgid to drop privileges |

### Resource Limits

```ini
LimitNOFILE=65536    # Max 65k file descriptors
MemoryMax=512M       # Max 512 MB RAM
CPUQuota=50%         # Max 50% CPU
TasksMax=256         # Max 256 tasks
```

## Attack Surface Minimization

### What LinMon CAN'T Do After Startup

After privilege drop, LinMon **cannot**:
- ❌ Load new BPF programs
- ❌ Modify system configuration
- ❌ Access files outside `/var/log/linmon/`
- ❌ Create new namespaces
- ❌ Execute arbitrary code (W^X enforcement)
- ❌ Regain root privileges
- ❌ Modify kernel parameters

### What LinMon CAN Do

LinMon retains minimal privileges:
- ✅ Read events from BPF ring buffer
- ✅ Write to log file (already opened as root)
- ✅ Resolve UIDs via /etc/passwd (cached)
- ✅ Process network packets (receive only)

## Threat Model

### Mitigated Threats

1. **Config File Tampering** → Permissions validated on load
2. **Path Traversal** → Log paths validated (no `..`)
3. **Privilege Escalation** → UID/GID dropped, capabilities cleared
4. **Resource Exhaustion** → Systemd limits (CPU, memory, FDs)
5. **Integer Overflow** → `strtoul()` with bounds checking
6. **Code Execution** → W^X enforcement, seccomp filtering

### Residual Risks

1. **BPF Program Bugs** → eBPF verifier provides safety guarantees
2. **Kernel Vulnerabilities** → Requires kernel patches
3. **Log File Disclosure** → Ensure `/var/log/linmon/` has proper permissions
4. **Disk Exhaustion** → Use logrotate to prevent logs from filling disk

## MITRE ATT&CK Coverage

LinMon provides comprehensive detection coverage for post-exploitation techniques. As of v1.4.1, LinMon detects **~95%** of common post-exploitation techniques used by attackers after initial compromise.

### Detection Capabilities by MITRE Technique

| Technique ID | Technique Name | Detection Method | Event Type | Default |
|-------------|----------------|------------------|------------|---------|
| **Persistence** | | | | |
| T1053 | Scheduled Task/Job | Writes to `/etc/cron.d/`, `/var/spool/cron/` | `security_persistence` | Off* |
| T1547.006 | Boot/Logon: Kernel Modules | `init_module()`, `finit_module()` syscalls | `security_module_load` | Off* |
| T1547 | Boot/Logon Autostart | Writes to systemd services, shell profiles, init scripts, autostart | `security_persistence` | Off* |
| **Privilege Escalation** | | | | |
| T1548.001 | Setuid and Setgid | `chmod +s` operations (fchmodat syscall) | `security_suid` | Off* |
| T1055 | Process Injection | `ptrace()` syscall (ATTACH, SEIZE, POKETEXT, POKEDATA) | `security_ptrace` | Off* |
| **Defense Evasion** | | | | |
| T1014 | Rootkit | eBPF program loading via `bpf()` syscall | `security_bpf` | Off* |
| T1036 | Masquerading | Process comm name vs actual executable mismatch | `comm_mismatch` field | Always |
| T1620 | Fileless Malware | `memfd_create()` + `execveat()` syscalls | `security_memfd`, `security_execveat` | Off* |
| T1574.006 | Hijack Execution Flow: LD_PRELOAD | Writes to `/etc/ld.so.preload` | `security_ldpreload` | **On** |
| **Credential Access** | | | | |
| T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | Reads of `/etc/shadow`, `/etc/gshadow` | `security_cred_read` | **On** |
| T1098.001 | Account Manipulation: /etc/shadow | Writes to `/etc/shadow`, `/etc/sudoers`, `~/.ssh/authorized_keys` | `security_cred_write` | **On** |
| T1098.004 | SSH Authorized Keys Backdoor | Writes to `~/.ssh/authorized_keys` | `security_cred_write` | **On** |
| T1552.004 | Private Keys | Reads of `~/.ssh/id_*` (rsa, ed25519, ecdsa) | `security_cred_read` | **On** |
| T1070.001 | Indicator Removal: Clear Linux Logs | Truncation/deletion of `/var/log/*` files | `security_log_tamper` | **On** |
| **Discovery** | | | | |
| T1082 | System Information Discovery | Process execution, network connections, file access | `process_exec`, `net_*`, `file_*` | On |
| **Lateral Movement** | | | | |
| T1021.004 | SSH | SSH connections, key reads, authorized_keys writes | `net_connect_tcp`, `security_cred_read` | **On** |
| **Collection** | | | | |
| T1040 | Network Sniffing | Raw socket creation (future enhancement) | - | - |
| **Command and Control** | | | | |
| T1071 | Application Layer Protocol | TCP/UDP network connections | `net_connect_tcp`, `net_send_udp` | On |
| T1571 | Non-Standard Port | Bind shell detection via `bind()` syscall | `security_bind` | Off* |
| **Exfiltration** | | | | |
| T1041 | Exfiltration Over C2 | Network connections tracked | `net_connect_tcp`, `net_send_udp` | On |
| **Impact** | | | | |
| - | Container Escape (T1611) | Namespace manipulation via `unshare()` syscall | `security_unshare` | Off* |

**Legend**:
- **On** = Enabled by default (recommended for all systems)
- Off* = Disabled by default (opt-in, enable based on threat model)
- Always = Always logged (no config flag, core functionality)

### Coverage Summary

**Enabled by Default** (~45% of techniques, high signal-to-noise):
- ✅ Credential file reads (shadow, sudoers, SSH keys) - T1003.008, T1552.004
- ✅ Credential file writes (account manipulation, SSH backdoors) - T1098.001, T1098.004
- ✅ Log tampering detection (anti-forensics) - T1070.001
- ✅ LD_PRELOAD rootkit detection - T1574.006
- ✅ Process masquerading detection - T1036
- ✅ Deleted executable detection - T1620
- ✅ Basic process/network monitoring

**Opt-In Detection** (~50% of techniques, may generate noise):
- ⚙️ Persistence mechanisms (cron, systemd, shell profiles)
- ⚙️ SUID/SGID manipulation
- ⚙️ Kernel module loading
- ⚙️ Process injection (ptrace)
- ⚙️ eBPF rootkit detection
- ⚙️ Fileless malware (memfd, execveat)
- ⚙️ Bind shell detection
- ⚙️ Container escape detection

### Configuration Recommendations

**High-Security Environments** (servers, production, bastion hosts):
```ini
# Enable all security monitors for maximum visibility
monitor_cred_read = true      # Credential theft (default: on)
monitor_cred_write = true     # Account manipulation (default: on)
monitor_log_tamper = true     # Log clearing/anti-forensics (default: on)
monitor_ldpreload = true      # LD_PRELOAD rootkit (default: on)
monitor_persistence = true    # Cron/systemd/shell profile persistence
monitor_suid = true           # SUID binary manipulation
monitor_modules = true        # Kernel module loading
monitor_ptrace = true         # Process injection
monitor_bpf = true            # eBPF rootkit detection
monitor_memfd = true          # Fileless malware
monitor_execveat = true       # Fileless execution
monitor_bind = true           # Bind shell detection
monitor_unshare = true        # Container escape
```

**Desktop/Workstation** (lower noise):
```ini
# Enable only high-value, low-noise detections
monitor_cred_read = true      # Credential theft
monitor_cred_write = true     # Account manipulation
monitor_log_tamper = true     # Log clearing
monitor_ldpreload = true      # LD_PRELOAD rootkit
monitor_persistence = true    # Persistence detection
monitor_suid = true           # SUID manipulation
# Leave others disabled to reduce noise from development tools
```

**Minimal Monitoring** (audit logging only):
```ini
# Only critical security detections (very low noise)
monitor_cred_read = true      # Credential theft (default: on)
monitor_cred_write = true     # Account manipulation (default: on)
monitor_log_tamper = true     # Log clearing (default: on)
monitor_ldpreload = true      # LD_PRELOAD rootkit (default: on)
monitor_processes = true      # Process execution logging
monitor_tcp = true            # Network connections
# All other security monitors disabled
```

### Detection Methodology

LinMon uses multiple detection layers:

1. **Behavioral Detection**: Monitors syscalls and kernel events
   - More robust than signature-based detection
   - Detects zero-day exploits using known techniques
   - Example: Any process writing to `/etc/cron.d/` triggers persistence alert

2. **Process Context Enrichment**: Adds security-relevant metadata
   - Package verification (dpkg/rpm) - detects unpackaged binaries
   - Binary hashing (SHA256) - tracks executable changes
   - Process masquerading - detects comm name manipulation
   - Deleted executables - detects fileless malware cleanup

3. **Smart Whitelisting**: Reduces false positives
   - Credential read detection: Whitelists system auth processes (sshd, login, sudo, etc.)
   - Process filtering: Configurable ignore lists for noisy applications
   - Network filtering: CIDR-based ignore lists for private networks

4. **Sparse Field Logging**: Only logs detection fields when relevant
   - `comm_mismatch` only present when process is masquerading
   - `deleted_executable` only present when binary deleted
   - `pkg_modified` only present when package file tampered
   - Reduces log volume and improves SIEM query performance

### Integration with SIEM

LinMon events map directly to MITRE ATT&CK techniques for SIEM correlation:

**Example Splunk Query** - Detect persistence attempts:
```spl
index=security sourcetype=linmon:json type=security_persistence
| stats count by persistence_type username path
| where count > 0
```

**Example Elasticsearch Query** - Detect privilege escalation chain:
```json
{
  "query": {
    "bool": {
      "should": [
        {"term": {"type": "security_cred_read"}},
        {"term": {"type": "security_suid"}},
        {"term": {"type": "priv_sudo"}}
      ]
    }
  }
}
```

**Example Alert Logic** - SSH key theft + outbound connection:
```
(type=security_cred_read AND cred_file=ssh_private_key)
FOLLOWED_BY
(type=net_connect_tcp FROM same_uid WITHIN 5_minutes)
```

## Log Management

LinMon includes a logrotate configuration to prevent disk exhaustion:

### Logrotate Configuration

Location: `/etc/logrotate.d/linmond`

**Features**:
- **Daily rotation** or when logs reach 100MB
- **30 days retention** (configurable)
- **Compression** of old logs (gzip)
- **Correct permissions** on rotated files (0640 nobody:nogroup)
- **Date-based naming** for easy identification

**Testing**:
```bash
# Test logrotate config syntax
sudo logrotate -d /etc/logrotate.d/linmond

# Force manual rotation (for testing)
sudo logrotate -f /etc/logrotate.d/linmond
```

**Customization**:
Edit `/etc/logrotate.d/linmond` to adjust:
- Rotation frequency (daily/weekly/monthly)
- Size threshold (100M default)
- Retention period (30 days default)

## Installation Security Checklist

**Note on Group Names**: Different Linux distributions use different group names for the unprivileged user:
- **Debian/Ubuntu**: Use `nobody:nogroup`
- **RHEL/Rocky/CentOS/AlmaLinux**: Use `nobody:nobody`

The Makefile and install.sh scripts automatically detect and use the correct group for your distribution.

```bash
# 1. Create log directory with proper permissions
sudo mkdir -p /var/log/linmon
# Ubuntu/Debian:
sudo chown nobody:nogroup /var/log/linmon
# RHEL/Rocky/CentOS:
# sudo chown nobody:nobody /var/log/linmon
sudo chmod 0750 /var/log/linmon

# 2. Create cache directory for package verification
sudo mkdir -p /var/cache/linmon
sudo chown nobody:nogroup /var/cache/linmon  # or nobody:nobody on RHEL
sudo chmod 0750 /var/cache/linmon

# 3. Secure config file
sudo mkdir -p /etc/linmon
sudo cp linmon.conf /etc/linmon/
sudo chown root:root /etc/linmon/linmon.conf
sudo chmod 0600 /etc/linmon/linmon.conf

# 4. Install binary
sudo cp build/linmond /usr/local/sbin/
sudo chown root:root /usr/local/sbin/linmond
sudo chmod 0755 /usr/local/sbin/linmond

# 5. Install hardened systemd service
sudo cp linmond.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now linmond

# 6. Install logrotate configuration
sudo cp linmond.logrotate /etc/logrotate.d/linmond
sudo chmod 0644 /etc/logrotate.d/linmond

# 7. Verify privilege drop
sudo journalctl -u linmond -n 20
# Look for: "✓ Dropped to UID/GID 65534 (nobody)"
#           "✓ Dropped all capabilities"
```

Or use the automated installer:
```bash
sudo ./install.sh
```

Or use make install:
```bash
sudo make install
```

## Audit Logging

LinMon startup logs security-relevant events:

```
LinMon starting...
Configuration:
  UID range: 1000-0 (0=unlimited)
...
✓ All monitoring programs attached
✓ Dropped to UID/GID 65534 (nobody)
✓ Dropped all capabilities (running with minimal privileges)
Monitoring active.
```

## Vulnerability Reporting

If you discover a security vulnerability, please report it to:
- **DO NOT** open a public GitHub issue
- Email: espegro@usit.uio.no
- Use GPG key: `50AE70D791320122` for sensitive disclosures
  - Fingerprint: Available at keys.openpgp.org
  - 4096 bit RSA key, created 2014-03-27
