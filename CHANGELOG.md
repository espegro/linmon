# Changelog

All notable changes to LinMon are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.6.2] - 2026-01-10

### Fixed

#### Security Hardening - Error Handling and Input Validation
- **Fixed missing error handling in file hash cache persistence** (`src/filehash.c`)
  - `fprintf()` calls in `filehash_save()` now check return values
  - Prevents corrupted cache file if disk is full or I/O errors occur
  - Properly cleans up (unlock mutex, close file, unlink temp) on write failure
  - **Severity**: HIGH - Could cause cache corruption on disk full conditions

- **Fixed insufficient input validation in SUDO_UID parsing** (`src/procfs.c`)
  - `strtoul()` conversion in `procfs_read_sudo_info()` now validates with `endptr`
  - Prevents accepting invalid data like `SUDO_UID=garbage` as UID 0
  - Checks that entire string was converted successfully
  - **Severity**: MEDIUM - Could allow privilege escalation tracking bypass

- **Added NULL pointer protection in process filtering** (`src/filter.c`)
  - `filter_should_log_process()` now checks for NULL `comm` parameter
  - Returns `false` safely instead of potential segfault
  - Defensive programming against caller errors
  - **Severity**: MEDIUM - Prevents crash on malformed input

- **Improved getpwuid_r() buffer handling** (`src/userdb.c`)
  - Increased buffer size from 2048 to 4096 bytes for systems with many groups
  - Added ERANGE error detection with warning message
  - Graceful fallback to `UID_XXX` format on buffer overflow
  - **Severity**: LOW - Improves compatibility on edge-case systems

**Credits**: Security audit findings from external code scanner (qwen2.5-coder:32b)

**Upgrade recommendation**: Recommended for all users. Fixes improve robustness and prevent edge-case failures.

## [1.6.1] - 2026-01-09

### Fixed

#### Critical Buffer Over-Read in Raw Disk Access Detection
- **Fixed buffer over-read vulnerability** in `is_raw_block_device()` eBPF function
- **Issue**: Array indices were accessed without verifying null-byte termination
  - Reading `path[6]`, `path[7]` without checking if string was long enough
  - Could read uninitialized stack memory for short paths like `/dev/s`
  - Would cause BPF verifier rejection in strict environments
- **Impact**:
  - Critical security fix - prevents undefined behavior in kernel space
  - Eliminates risk of BPF program load failures
  - Required for production deployment
- **Fix details**:
  - Added null-byte checks before all array index accesses
  - Validates string length incrementally before reading each character
  - BPF verifier now accepts program without issues
- **Files changed**: `bpf/linmon.bpf.c` (51 insertions, 15 deletions)

#### Improved Device Path Validation
- **Enhanced validation** to prevent false positives from invalid device paths
- **Previous behavior**: `/dev/sdFOOBAR` would incorrectly match as valid disk
- **Fixed validation** for all device types:
  - SCSI/SATA (`/dev/sd*`): Verify next char is null-terminator or partition digit
  - NVMe (`/dev/nvme*`): Check minimum length and validate `nvme[0-9]n[0-9]` format
  - Virtio (`/dev/vd*`): Validate partition number suffix
  - Xen (`/dev/xvd*`): Check string length before accessing drive letter
  - MMC/SD (`/dev/mmcblk*`): Verify all required characters exist before access
  - Device Mapper (`/dev/dm-*`): Null-check before device number validation
  - Loop devices (`/dev/loop*`): Validate length before accessing device number
- **Result**: More precise detection, eliminates false positives

**Upgrade recommendation**: All v1.6.0 users should upgrade immediately to fix buffer over-read.

## [1.6.0] - 2026-01-08

### Added

#### Raw Disk Access Detection (T1561.001/002 - Disk Wipe)
- **Detects write access to raw block devices** to identify disk wipe attacks, ransomware destructive payloads, and anti-forensics activity
- **Monitored device types**:
  - SCSI/SATA disks: `/dev/sd*` (whole disks and partitions)
  - NVMe disks: `/dev/nvme*`
  - Virtio block devices: `/dev/vd*`
  - Xen virtual block devices: `/dev/xvd*`
  - MMC/SD cards: `/dev/mmcblk*`
  - Software RAID: `/dev/md*`
  - Device mapper (LVM, LUKS): `/dev/dm-*`
  - Loop devices: `/dev/loop*`
- **Implementation**:
  - eBPF `openat()` syscall monitoring for `O_WRONLY`/`O_RDWR` flags
  - Pattern matching in kernel space using `is_raw_block_device()` helper
  - Both tracepoint and kprobe versions for RHEL compatibility
  - Rate limiting and UID filtering applied
- **Configuration**: `monitor_raw_disk_access = true` (enabled by default)
- **Event type**: `raw_disk_access`
- **Event fields**: `device` (path), `open_flags`, `write_access` (boolean)
- **Use cases**:
  - Ransomware final stage: Wiping MBR/GPT to prevent recovery
  - Sabotage: `dd if=/dev/zero of=/dev/sda`
  - Anti-forensics: `shred /dev/nvme0n1`
  - Destructive malware: Disk wipers in targeted attacks
- **Performance**: Low noise - legitimate writes to raw devices are rare (disk imaging, installers, encryption setup)

**Example event**:
```json
{
  "type": "raw_disk_access",
  "pid": 12345,
  "uid": 0,
  "comm": "dd",
  "device": "/dev/sda",
  "open_flags": 2,
  "write_access": true
}
```

### Changed

#### Security Hardening: Eliminated Shell Injection Risks in Package Queries
- **Replaced `popen()` with `fork()+execve()`** for all package manager queries
- **Security improvement**: Completely eliminates shell injection attack surface
- **Implementation details**:
  - Direct `execve()` calls with argument arrays (no shell interpretation)
  - Pipe-based IPC for parent-child communication
  - Proper process cleanup with `waitpid()`
  - Exit status validation before trusting output
- **Affected code**: `src/pkgcache.c` - Package verification cache
- **Tested with**: dpkg (Debian/Ubuntu) and rpm (RHEL/Rocky) package managers
- **Impact**: No functional changes, purely security improvement
- **Technical note**: Follows principle of least authority - never invoke shell when direct syscalls suffice

## [1.5.0] - 2026-01-08

### Added

#### Example Configurations for Common Use Cases
- **Five pre-configured examples** in `examples/configs/` directory
- `desktop.conf`: Personal laptop/desktop (50-200 events/day, <1% CPU)
  - Monitors only logged-in user (UID >= 1000)
  - Filters browser/IDE thread noise
  - Selective security detections (excludes debuggers)
- `bastion.conf`: SSH bastion/jump server (200-1000 events/day, 1-3% CPU)
  - Monitors ALL users including root
  - Comprehensive credential theft detection
  - Extended log retention (30 days)
- `server.conf`: Web/app/database server (200-500 events/day, 0.5-2% CPU)
  - Balanced security with low noise
  - Thread filtering for multi-threaded apps
  - Optimized for production workloads
- `container-host.conf`: Docker/Kubernetes host (500-2000 events/day, 2-5% CPU)
  - Container metadata capture enabled
  - vsock and namespace manipulation monitoring
  - Kubernetes pod-level correlation support
- `paranoid.conf`: Maximum security/forensics (5000-50000+ events/day, 5-20% CPU)
  - ALL monitoring enabled (processes, files, network, UDP)
  - NO filtering (maximum visibility)
  - For incident response and high-security environments
- **Comprehensive README** in `examples/configs/README.md` with selection guide and tuning tips

#### Container Awareness and Metadata Enrichment
- **Container runtime detection** from namespace inodes and cgroup parsing
- Automatic detection of: Docker, Podman, Kubernetes, containerd, LXC, systemd-nspawn
- **Sparse field logging**: Container metadata only added when process is containerized
  - Host processes: Zero JSON overhead (only 16 bytes in ring buffer)
  - Container processes: +150 bytes avg with full metadata
- **Event fields added**:
  - `container.runtime`: Runtime type (docker, podman, kubernetes, etc.)
  - `container.id`: Full container ID (64-char hex for Docker/Podman)
  - `container.pod_id`: Kubernetes pod UUID (if applicable)
  - `container.ns_pid`: PID namespace inode (for correlation)
  - `container.ns_mnt`: Mount namespace inode
  - `container.ns_net`: Network namespace inode
- **eBPF implementation**:
  - Added namespace inode fields to all event structures
  - New `FILL_NAMESPACE_INFO()` macro reads pid_ns, mnt_ns, net_ns from task->nsproxy
  - Applied to all 30+ event handlers (process, file, network, privilege, security)
- **Userspace implementation**:
  - `containerinfo.c`: Parses `/proc/<pid>/cgroup` for runtime and container ID
  - Pattern matching for multiple cgroup formats (systemd, cgroupsv2, legacy)
  - `containerinfo_is_in_container()`: Fast inline check comparing namespace inodes
  - Integrated into all logger functions with fail-safe error handling
- **Configuration**: `capture_container_metadata = true` (enabled by default)
- **Performance**: ~0.1ms overhead per containerized event, zero for host processes
- **Use cases**:
  - Container escape detection (process starts in container, later in host namespace)
  - Lateral movement tracking across container boundaries
  - Kubernetes pod-level correlation of security events
  - SIEM enrichment for multi-container environments

**Example event**:
```json
{
  "type": "process_exec",
  "comm": "curl",
  "filename": "/usr/bin/curl",
  "container": {
    "runtime": "docker",
    "id": "73d7126417b3d3c070cacf2be27eb576620365c8545c73b7b4aa63760be0b586",
    "ns_pid": 4026534902,
    "ns_mnt": 4026534899,
    "ns_net": 4026534904
  }
}
```

### Fixed

#### Security Hardening of Container Detection Code
- **NULL pointer dereference** (HIGH): Fixed unsafe pointer arithmetic in `extract_container_id()`
  - Replaced `strchr()` chain with safe parsing and length validation
  - Separate handling for `/docker-` and `/docker/` patterns
- **Buffer overflow** (CRITICAL): Increased cgroup buffer from 512 to PATH_MAX (4096 bytes)
  - Kubernetes cgroup paths can exceed 512 bytes
  - Prevents truncation and parsing errors
- **fprintf() validation** (MEDIUM): Added error checking to all fprintf() calls in `log_container_info()`
  - Uses existing `check_fprintf_result()` helper
  - Graceful degradation on write failures (attempts to close JSON object)
- **Minimum ID length validation** (MEDIUM): Reject container IDs shorter than 12 hex chars
  - Prevents false positives from short pattern matches
  - Docker/Podman IDs are 64 chars, accept >= 12 for short ID support
- **Namespace inode validation** (MEDIUM): Added zero-check in `containerinfo_is_in_container()`
  - Detects corrupted or invalid eBPF data
  - Returns false if any namespace inode is zero
- **containerd fallback logic** (LOW): Fixed runtime detection when container ID unavailable
  - Now returns true when containerd detected even without extractable ID
  - Consistent with other runtime detection behaviors
- **Dead code removal** (LOW): Removed unreachable duplicated condition in `containerinfo_get()`
  - Cleaned up `if (!found && !found)` logic error

### Technical Details

**eBPF Changes**:
- Added namespace constants to `bpf/common.h`: PROC_PID_INIT_INO (4026531836), PROC_MNT_INIT_INO (4026531840), PROC_NET_INIT_INO (4026531841)
- Added namespace fields to all event structures: `__u32 pid_ns, mnt_ns, net_ns`
- Macro `FILL_NAMESPACE_INFO()` reads from `task->nsproxy` using CO-RE for kernel portability
- Initializes to init namespace values, then reads actual values if nsproxy exists

**Userspace Changes**:
- New files: `src/containerinfo.c`, `src/containerinfo.h`
- Updated: `src/logger.c` (added `log_container_info()`), `src/config.c`, `src/main.c`
- Container detection only attempted if namespace differs from init (performance optimization)
- Pattern matching supports:
  - Docker: `/docker-<id>` or `/docker/<id>`
  - Podman: `/libpod-<id>`
  - Kubernetes: `/kubepods.../pod<uuid>/.../cri-containerd-<id>`
  - containerd: `/containerd.service/...`
  - LXC: `/lxc/<name>`
  - systemd-nspawn: `/machine-<name>`

**Configuration**:
- Added to `linmon.conf` and `linmon.conf.example`
- Default enabled (essential for container environments)
- Can be disabled for non-containerized hosts to save minimal overhead

## [1.4.2] - 2026-01-06

### Fixed

**Critical bugfix: Credential read detection false positives**
- Fixed excessive `security_cred_read` events for non-credential files
- Bug: Missing `cred_type == 0` check in credential READ section (bpf/linmon.bpf.c:2259)
- Impact: ALL non-write-only file opens were logged with `"cred_file":"unknown"`
  - `/etc/ld.so.cache`, shared libraries, locale files, `/proc/*/cmdline`, etc.
  - Generated thousands of false positive events per hour
- Root cause: Credential READ handler checked operation flags but not file type
- Fix: Added 4-line check matching existing pattern used by credential WRITE handler
- After fix: Zero false positives, only actual credential file access logged
- Code review: Verified all other security handlers have correct file type checks

**Details:**
```diff
+ // Only monitor actual credential files
+ if (cred_type == 0)
+     return 0;  // Not a credential file
+
  // We want to detect READs - any open that's not purely write
  if ((flags & O_WRONLY) && !(flags & O_RDWR))
      return 0;  // Write-only, not interesting for credential theft
```

The bug was introduced in v1.4.1 when credential WRITE detection was added. The READ section was updated to detect both reads and writes but lost the file type validation check.

## [1.4.1] - 2026-01-06

### Added

#### Credential File WRITE Detection (T1098.001 - Account Manipulation)
- New event type: `EVENT_SECURITY_CRED_WRITE` (26)
- Detects writes to authentication/authorization files
- Config flag: `monitor_cred_write = true` (enabled by default)
- Monitored files:
  - `/etc/shadow`, `/etc/gshadow` - Password hash modification
  - `/etc/sudoers`, `/etc/sudoers.d/*` - Sudo privilege escalation
  - `/etc/ssh/*` - SSH system configuration tampering
  - `/etc/pam.d/*` - PAM authentication backdoors
  - `~/.ssh/id_*` - SSH private key replacement
  - `~/.ssh/authorized_keys` - SSH backdoor installation (T1098.004)
  - `~/.ssh/config` - SSH configuration hijacking
- Event fields:
  - cred_file: File type (shadow, gshadow, sudoers, ssh_authorized_keys, etc.)
  - path: Full file path
  - open_flags: File open flags (O_WRONLY, O_RDWR, O_CREAT, O_TRUNC)
- Use case: Detect account manipulation, password changes, SSH backdoors

#### Log File Tampering Detection (T1070.001 - Log Clearing / Anti-Forensics)
- New event type: `EVENT_SECURITY_LOG_TAMPER` (27)
- Detects attempts to cover tracks by deleting or truncating log files
- Config flag: `monitor_log_tamper = true` (enabled by default)
- Detection methods:
  - **Truncation**: Detects O_TRUNC flag on `/var/log/*` files (e.g., `> /var/log/auth.log`)
  - **Deletion**: Detects unlink/rm operations on `/var/log/*` files
- Smart filtering: Whitelists legitimate log managers to avoid false positives
  - logrotate, rsyslogd, systemd-journal, syslog-ng, auditd, linmond
- Event fields:
  - tamper_type: "truncate" or "delete"
  - path: Log file path
  - open_flags: File open flags (for truncate events)
- Use case: Detect attackers covering their tracks after compromise

### Technical Details

**eBPF Implementation:**
- Credential write detection: Extended `handle_security_openat()` to detect writes before reads
- Log tampering detection:
  - Truncate: Checks O_TRUNC flag in `handle_security_openat()`
  - Delete: Monitors unlink in `handle_unlinkat_common()`
  - Helper functions: `is_log_file()`, `is_legit_log_manager()` for whitelist filtering
- Both features use existing `struct security_event` with `extra` field for sub-types
- No new BPF maps required - leverages existing infrastructure

**Userspace:**
- Logger: Added JSON formatting for `security_cred_write` and `security_log_tamper` events
- Config: Added `monitor_cred_write` and `monitor_log_tamper` flags (default: true)
- Documentation: Updated MONITORING.md and SECURITY.md

### Changed

**MITRE ATT&CK Coverage:**
- Increased from ~92% to ~95% of post-exploitation techniques
- Added T1098.001 (Account Manipulation: /etc/shadow)
- Added T1098.004 (SSH Authorized Keys Backdoor)
- Added T1070.001 (Indicator Removal: Clear Linux Logs)
- Updated "Enabled by Default" coverage from ~40% to ~45%

**Configuration:**
- Both new features enabled by default due to:
  - Very low false positive rate
  - High security value
  - Whitelisting of legitimate system processes
  - Minimal performance overhead

### Known Limitations

- **Path traversal**: `/etc/../etc/shadow` bypasses detection (syscall-level monitoring limitation)
- **Symlinks**: Symlinks to credential/log files bypass detection
- These are documented trade-offs for eBPF syscall monitoring vs LSM hooks

## [1.4.0] - 2026-01-06

### Added

#### User SSH Keys Detection (T1552.004, T1098.004)
- Extended credential monitoring to detect ~/.ssh/* access
  - Private key reads: ~/.ssh/id_rsa, ~/.ssh/id_ed25519, ~/.ssh/id_ecdsa
  - Authorized keys backdoor: ~/.ssh/authorized_keys (write access)
  - SSH config hijacking: ~/.ssh/config (ProxyCommand abuse)
- Uses existing `monitor_cred_read = true` flag (no new config needed)
- Extends `EVENT_SECURITY_CRED_READ` with new cred_file types:
  - ssh_private_key (type 6)
  - ssh_authorized_keys (type 7)
  - ssh_user_config (type 8)
- Critical for bastion/jump host security

#### SUID/SGID Manipulation Detection (T1548.001)
- New event type: `EVENT_SECURITY_SUID` (25)
- Detects chmod operations that set SUID (04000) or SGID (02000) bits
- Monitors fchmodat syscall for privilege escalation setup
- Config flag: `monitor_suid = false` (opt-in)
- Event fields:
  - path: File being modified
  - mode: Full mode bits
  - suid: Boolean (true if SUID bit set)
  - sgid: Boolean (true if SGID bit set)
- Use case: Detect attackers creating SUID binaries for persistent root access

#### Persistence Mechanism Detection (T1053, T1547)
- New event type: `EVENT_SECURITY_PERSISTENCE` (24)
- Dedicated detection for persistence locations (separate from general file monitoring)
- Config flag: `monitor_persistence = false` (opt-in)
- Detects writes to:
  - **Cron** (type 1): /etc/cron.d/*, /var/spool/cron/*
  - **Systemd** (type 2): /etc/systemd/system/*, /usr/lib/systemd/system/*
  - **Shell profiles** (type 3): ~/.bashrc, ~/.profile, ~/.bash_profile, ~/.zshrc
  - **Init scripts** (type 4): /etc/rc.local, /etc/init.d/*
  - **Autostart** (type 5): ~/.config/autostart/*
- Event fields:
  - path: File being written
  - persistence_type: cron, systemd, shell_profile, init, autostart
  - open_flags: File open flags
- Low noise: Only logs specific persistence paths (not all file activity)

### Technical Details

**eBPF Implementation:**
- SSH key detection: Extended `get_cred_file_type()` with /.ssh/ substring scanning
- SUID detection: Monitors fchmodat syscall, filters on mode & 06000 (S_ISUID | S_ISGID)
- Persistence detection: `get_persistence_type()` with character-by-character path matching
  - Prefix matching for /etc/*, /var/*, /usr/* paths
  - Substring scanning for shell profiles (handles varying home directories)
  - #pragma unroll loop for BPF verifier compatibility

**Userspace:**
- Added `logger_log_persistence_event()` with persistence_type name mapping
- Extended security_event logger with SUID mode bit decoding
- Config validation and default values (both persistence and SUID default to false)

**Documentation:**
- linmon.conf.example: Detailed descriptions with use cases and recommendations
- All three features documented with MITRE ATT&CK technique IDs

### Security Impact

**Overall Coverage:**
- Extends MITRE ATT&CK coverage from ~87% to ~92% of post-exploitation techniques
- Addresses key gaps in persistence and privilege escalation detection
- Complements existing credential monitoring with SSH-specific detection

**Detection Scenarios:**
1. **SSH Key Theft**: Attacker reads ~/.ssh/id_rsa for lateral movement
2. **SSH Backdoor**: Attacker writes ~/.ssh/authorized_keys for persistent access
3. **Cron Persistence**: Attacker creates /etc/cron.d/backdoor for scheduled execution
4. **Systemd Persistence**: Attacker installs malicious systemd service
5. **Shell Profile Persistence**: Attacker modifies ~/.bashrc for auto-execution on login
6. **SUID Escalation**: Attacker runs `chmod +s /tmp/backdoor` for persistent root

### Example Events

**SSH Private Key Read:**
```json
{
  "type": "security_cred_read",
  "cred_file": "ssh_private_key",
  "path": "/home/alice/.ssh/id_rsa",
  "uid": 1001,
  "username": "attacker",
  "comm": "cat"
}
```

**Cron Persistence:**
```json
{
  "type": "security_persistence",
  "persistence_type": "cron",
  "path": "/etc/cron.d/backdoor",
  "uid": 0,
  "username": "root",
  "comm": "echo",
  "open_flags": 577
}
```

**SUID Manipulation:**
```json
{
  "type": "security_suid",
  "path": "/tmp/exploit",
  "mode": 35309,
  "suid": true,
  "sgid": false,
  "uid": 0,
  "username": "root",
  "comm": "chmod"
}
```

## [1.3.3] - 2026-01-06

### Added
- Process masquerading detection - New comm_mismatch field
  - Detects when processes change comm name via prctl() to impersonate other programs
  - Smart prefix matching handles TASK_COMM_LEN truncation (15 char max)
  - Compares kernel comm name vs actual executable from /proc/<pid>/exe
  - Only logged when mismatch detected (sparse field for efficiency)
  - Works across all event types: network, privilege, security events

- Deleted executable detection - New deleted_executable field
  - Detects when process executable is deleted while running
  - Indicator of fileless malware or post-exploitation cleanup
  - Reads from /proc/<pid>/exe symlink marked with (deleted) suffix
  - Only logged when detected (sparse field)

### Changed
- CAP_SYS_PTRACE capability now retained after privilege drop
  - Enables reading /proc/<pid>/exe for processes across all users
  - Required for masquerading detection in network/privilege/security events
  - Uses ambient capabilities (kernel >= 4.3) for UID transition
  - SECBIT_NO_SETUID_FIXUP + SECBIT_KEEP_CAPS prevent capability clearing
  - CAP_SETUID and CAP_SETGID explicitly dropped after UID change
  - Security verification ensures cannot regain root privileges

### Technical Details
- Smart comm matching: prefix-match for names > 15 chars, full match otherwise
- Ambient capability requires PERMITTED + EFFECTIVE + INHERITABLE sets
- Securebits locked with _LOCKED variants to prevent modification
- Detection works on: net_connect_tcp, net_accept_tcp, net_send_udp, net_vsock_connect, priv_setuid, priv_setgid, priv_sudo, all security_* events
- Process exec events continue to use filename field (already available at exec time)

### Security Impact
- Medium severity enhancement: Detects process impersonation attacks
- Examples: malware masquerading as systemd, Chrome, or other trusted processes
- Combines with existing package verification and binary hashing for defense-in-depth
- CAP_SYS_PTRACE addition: minimal attack surface (read-only /proc access)
- Extensive testing: verified capability setup, UID drop, and regain-root prevention

### Example Detection
```json
{
  "type": "net_connect_tcp",
  "comm": "systemd",
  "process_name": "malware",
  "comm_mismatch": true,
  "daddr": "192.0.2.1"
}
```

## [1.3.2] - 2026-01-05

### Added
- **BPF load failure logging** - Enhanced detection of rootkit interference
  - Logs to syslog with `LOG_CRIT` priority when BPF programs fail to load
  - Creates persistent alert file: `/var/log/linmon/CRITICAL_BPF_LOAD_FAILED`
  - Detailed stderr output with troubleshooting steps
  - Explicitly mentions "Singularity" rootkit in error messages
  - Success path logs: "BPF programs loaded successfully (no interference detected)"
  - Enables detection when rootkits block `bpf()` syscall (e.g., Singularity)

- **Core vs Extras architecture** - Clear separation of required vs optional features
  - Created `extras/` directory for optional integrations
  - Moved LKRG integration scripts to `extras/lkrg/`
  - Added comprehensive `extras/lkrg/README.md` with installation and usage
  - LKRG is now clearly documented as optional (not required for core functionality)

### Changed
- **Zero runtime dependencies** - Documentation now emphasizes LinMon core has no external dependencies
  - Updated README.md with "Core vs Optional Features" section
  - Updated ROOTKIT_PREVENTION.md to separate core (Layers 1-5) from optional (Layer 6: LKRG)
  - Updated scripts/README.md to clearly mark LKRG as optional
  - All monitoring and detection works standalone without LKRG

### Technical Details
- BPF load failure creates forensic evidence that survives daemon exit
- Alert file includes timestamp, hostname, kernel version, and investigation steps
- Uses `gethostname()` and `uname()` for system information (no config struct dependency)
- Syslog logging ensures tamper-resistant audit trail
- LKRG scripts in `extras/lkrg/`: `linmon-enable-lockdown.sh`, `linmon-check-lockdown.sh`, `setup-failure-alerting.sh`, `linmon-failure-alert.sh`

### Security Impact
- **High severity enhancement**: Detects when rootkits prevent LinMon from loading
- Provides forensic evidence for incident response
- Makes rootkit interference immediately visible in syslog/journald
- Complements LKRG's optional runtime protection with core detection capability

## [1.3.1] - 2025-12-28

### Fixed
- **Package cache TTL** - Added 24-hour time-to-live for cache entries
  - Prevents stale package information after legitimate upgrades
  - Cache entries now expire after 24 hours and are re-queried
  - Existing detection (inode/mtime change) still works for immediate invalidation
  - Backward compatible with v1 cache format (auto-upgrades to v2)

### Technical Details
- Added `cached_at` timestamp to cache entries
- Cache lookup checks: `(now - cached_at) > 24h` for expiration
- Cache file format upgraded to v2 with backward compatibility
- Old v1 cache files are automatically migrated on load

### Impact
- **Medium severity bugfix**: Eliminates false positives after package upgrades
- Improves reliability of package verification feature
- No performance impact (queries only happen on cache miss or expiration)

## [1.3.0] - 2025-12-28

### Added
- **vsock monitoring support** - Monitor VM-to-host and container-to-host communication via Virtual Sockets
  - New config option: `monitor_vsock` (default: false)
  - Detects communication between VMs/containers and host system
  - Critical for detecting container escape attempts (MITRE ATT&CK T1611)
  - Useful for detecting VM-based C2 communication and lateral movement
  - New event type: `net_vsock_connect` with CID (Context ID) and port information

### Technical Details
- Added `AF_VSOCK` constant and `EVENT_NET_VSOCK_CONNECT` event type
- Implemented eBPF kprobe on `vsock_connect()` kernel function
- Reuses existing `network_event` structure (CIDs stored in address fields)
- Logger handles AF_VSOCK family to format CIDs as decimal numbers
- Conditional probe attachment based on `monitor_vsock` config option

### Security Use Cases
- **Container escape detection**: Detect unauthorized vsock communication from containers
- **VM-to-host monitoring**: Track which VMs communicate with host services
- **Lateral movement**: Identify suspicious cross-VM communication patterns
- **C2 detection**: Detect malware using vsock for command and control

### Event Example
```json
{
  "type": "net_vsock_connect",
  "pid": 1234,
  "ppid": 1000,
  "uid": 1000,
  "comm": "suspicious_app",
  "saddr": "3",
  "daddr": "2",
  "sport": 12345,
  "dport": 2049,
  "family": 40
}
```

In this example, a process in VM with CID 3 is connecting to host (CID 2) on port 2049.

### Configuration
Add to `/etc/linmon/linmon.conf` to enable:
```
monitor_vsock = true
```

## [1.2.7] - 2025-12-28

### Added
- **Process context fields for all event types** - Added `ppid`, `sid`, `pgid`, `tty` to file, network, privilege, and security events
  - File events: Now include parent PID, session ID, process group ID, TTY
  - Network events: Now include parent PID, session ID, process group ID, TTY
  - Privilege events: Now include parent PID, session ID, process group ID, TTY
  - Security events: Now include parent PID, session ID, process group ID, TTY
  - Enables better SIEM correlation and incident response
  - Consistent event schema across all event types

### Changed
- All event types now have consistent process context matching `process_event`
- JSON schema is now uniform - all events have same baseline fields

### Technical Details
- Added `FILL_PROCESS_CONTEXT` macro in eBPF for code reuse
- Modified all event structures in `bpf/common.h` to include new fields
- Updated all eBPF event handlers to populate process context
- Updated all logger functions in `src/logger.c` to output new fields in JSON

### Benefits
- **Easier SIEM analysis**: Directly see parent process, session, process group for all events
- **Better incident response**: Track process hierarchies without additional lookups
- **Improved alerting**: Correlate network activity with parent processes
- **Consistent schema**: Same fields across all event types simplifies parsing

### Example
```json
{
  "type": "net_connect_tcp",
  "pid": 12346,
  "ppid": 12345,
  "sid": 12345,
  "pgid": 12345,
  "tty": "pts/0",
  "comm": "curl",
  "daddr": "1.2.3.4",
  "dport": 443
}
```

Now you can see that curl (PID 12346) was started by bash (PPID 12345) in session 12345.

## [1.2.6] - 2025-12-28

### Fixed
- **Package verification false positives on UsrMerge systems** - Fixed package detection for hardlinked binaries
  - Modern Ubuntu/Debian use UsrMerge: `/bin` → `/usr/bin` symlinks
  - Package manifests only list canonical paths (e.g., `/bin/ss`)
  - Hardlinks to `/usr/bin/ss` were incorrectly reported as `"package":null`
  - Implemented UsrMerge-aware path normalization with 3-tier fallback:
    1. Try normalized path (`/usr/bin/foo` → `/bin/foo`)
    2. Try original path (for non-UsrMerge systems)
    3. Try realpath (handles symlinks and hardlinks)
  - Eliminates false positives for bastion host monitoring

### Technical Details
- Added `detect_usrmerge()` to check if system uses UsrMerge
- Added `normalize_usrmerge_path()` for path translation
- Refactored `query_package_manager()` with `try_package_query()` helper
- Handles `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/lib64` conversions
- Example: `/usr/bin/ss` now correctly reports `"package":"iproute2"`

## [1.2.5] - 2025-12-27

### Fixed
- **JSON schema consistency** - `process_name` field is now always present in all event types
  - Previously omitted entirely when `readlink(/proc/<pid>/exe)` failed
  - Now outputs `"process_name":null` when unavailable (consistent schema)
  - Affects: network, privilege, and security events
  - Fixes JSON parser compatibility issues

### Technical Details
- Short-lived processes (curl, grep) often exit before event is logged
- Race condition: eBPF event fires → daemon reads /proc → process already gone
- Field is now: `"process_name":"value"` or `"process_name":null`
- process_exec events always have process_name (from eBPF filename field)

## [1.2.4] - 2025-12-27

### Fixed
- **Critical bugfix: process_name extraction** - Fixed `process_name` showing "exe" for processes with manipulated argv[0]
  - Switched from reading `/proc/<pid>/cmdline` to `readlink(/proc/<pid>/exe)`
  - Chrome child processes now correctly show `"google-chrome-stable"` instead of `"exe"`
  - `readlink()` returns actual executable path (not manipulable argv[0])
  - Works without CAP_SYS_PTRACE (only needs symlink read permission)

### Changed
- Updated documentation to reflect readlink-based implementation (README.md, CLAUDE.md)

## [1.2.3] - 2025-12-26

### Added
- **process_name field** - Added to all event types (process, network, file, privilege, security)
  - Always available for process_exec/process_exit events (from eBPF filename field)
  - Best-effort for network/privilege/security events (reads /proc/<pid>/exe)
  - Provides full executable basename without 16-char comm truncation
  - Fail-safe design: field omitted if unavailable (no crashes or corrupt data)
- **SELinux support for RHEL/Rocky** - Pre-built binaries now work out-of-the-box
  - `install.sh` auto-detects SELinux and runs `restorecon` on binaries and directories
  - Sets correct contexts: `bin_t` for executable, proper log/cache directory contexts
  - Added comprehensive SELinux troubleshooting guide to INSTALL.md

### Technical
- `src/logger.c`: Added `get_process_name_from_proc()` function for /proc reading
- Hidepid detection at startup warns if process_name may be unavailable
- All logger functions include process_name where applicable

## [1.2.2] - 2025-12-26

### Added
- **Tamper detection and integrity monitoring**
  - Event sequence numbers (`seq` field) on all events to detect deleted events
  - Periodic checkpoints every 30 min with daemon SHA256, config SHA256, uptime
  - Checkpoints logged to both JSON and syslog/journald (harder to tamper)
  - Detects: deleted events (seq gaps), binary replacement, config tampering
- **Integrity hashing**
  - Daemon binary SHA256 calculated at startup (detects binary replacement)
  - Config file SHA256 tracked and logged at checkpoints and SIGHUP reload
  - Recalculated at each checkpoint to detect silent config changes

### Changed
- All events now include monotonic `seq` field for tamper detection
- Daemon lifecycle events include integrity hashes (daemon_start, daemon_reload, daemon_shutdown)
- SIGHUP reload now logs config hash before/after (audit trail)

### Technical
- `src/logger.c`: Added event_sequence counter and event_count tracking
- `src/main.c`: Checkpoint logic, daemon/config hash calculation
- `src/config.c`: Added `checkpoint_interval` option (default: 30 minutes)

## [1.1.2] - 2025-12-25

### Fixed
- **Event dropping under load** - Increased rate limiting thresholds to prevent event loss
  - Token bucket burst: 20 → 50 events
  - Refill rate: 100 → 200 events/sec
  - Ring buffer: 256KB → 1MB
- UID 0 (root) events were being dropped due to shared token bucket across system processes

## [1.1.1] - 2025-12-25

### Added
- **Sudo session tracking** - `sudo_uid` and `sudo_user` fields in process_exec events
- eBPF-based environment scanning to detect SUDO_UID (no capabilities required)
- Enables tracking user activity across sudo privilege escalation

### Technical
- Scans up to 4KB of process environment at exec time
- Uses bounded loops with #pragma unroll for BPF verifier compatibility
- Works with large LS_COLORS environment variables

## [1.1.0] - 2025-12-25

### Added
- CHANGELOG.md following Keep a Changelog format
- VERSION file as single source of truth for version number
- Shutdown statistics logging (cache hits/misses, events processed)

### Changed
- Improved default configuration for better security:
  - `min_uid = 0` (monitor all users including root)
  - `monitor_process_exit = false` (reduce noise)
  - `monitor_modules = true` (high-value security events)
  - `monitor_bpf = true` (detect eBPF rootkits)
  - Added common private network ranges to `ignore_networks`

### Fixed
- Package cache directory now properly created during installation
- Systemd service now has write access to `/var/cache/linmon`

## [1.0.17] - 2025-12-25

### Added
- Persistent SHA256 hash cache that survives daemon restarts
- Configurable cache options: `hash_cache_file`, `hash_cache_size`, `cache_save_interval`
- Periodic cache saves (default: every 5 minutes)
- Cache saved on SIGHUP config reload

### Fixed
- Package cache not writing due to systemd `ProtectSystem=strict`

## [1.0.16] - 2025-12-24

### Added
- Security hardening: privilege dropping after BPF load
- Drops to UID/GID 65534 (nobody) after initialization
- Clears all capabilities after BPF programs attached
- Supplementary group dropping for defense-in-depth

### Security
- Daemon runs with zero capabilities after startup
- Cannot regain root privileges after dropping

## [1.0.15] - 2025-12-24

### Added
- Full syslog support for all events via `log_to_syslog` config option
- Events logged to both JSON file and syslog/journald when enabled
- Daemon lifecycle events always logged to syslog for tamper detection

### Changed
- Syslog integration now optional (off by default for normal events)

## [1.0.14] - 2025-12-24

### Added
- Tamper detection: daemon lifecycle events logged to syslog/journal
- Signal sender information captured (PID, UID) for shutdown/reload events
- `daemon_start`, `daemon_shutdown`, `daemon_reload` events

### Security
- Attackers stopping linmond will be logged to system journal

## [1.0.13] - 2025-12-23

### Added
- Hostname field in all events for multi-host deployments
- SIEM integration examples in `extras/` directory:
  - Vector configuration for log shipping
  - ClickHouse schema for analytics
  - Filebeat configuration
  - Splunk integration

## [1.0.12] - 2025-12-23

### Security
- Fixed multiple pkgcache vulnerabilities
- Input validation for package names
- Protection against path traversal

### Added
- Comprehensive installation guide (INSTALL.md)

## [1.0.11] - 2025-12-23

### Security
- Fixed command injection vulnerability in package lookup
- Package names now validated before shell execution

## [1.0.10] - 2025-12-22

### Added
- Package verification for executed binaries
- `verify_packages` config option
- `package` and `pkg_modified` fields in process events
- Detects if binary was modified since package installation

## [1.0.9] - 2025-12-22

### Added
- Credential file monitoring (`monitor_cred_read`)
- Detects reads of /etc/shadow, /etc/sudoers, SSH configs, PAM configs
- Smart whitelisting of legitimate auth processes

## [1.0.8] - 2025-12-21

### Added
- Credential theft detection (T1003.008)
- LD_PRELOAD rootkit detection (T1574.006)
- `security_cred_read` and `security_ldpreload` event types

## [1.0.7] - 2025-12-21

### Added
- Session tracking with session ID field
- Extended security monitoring options
- Built-in log rotation (configurable size and count)
- `log_rotate`, `log_rotate_size`, `log_rotate_count` options

## [1.0.6] - 2025-12-20

### Added
- MITRE ATT&CK security monitoring:
  - T1055: Process Injection (ptrace monitoring)
  - T1547.006: Kernel Module Loading
  - T1620: Fileless Malware (memfd_create)
  - T1571: Bind Shell Detection
  - T1611: Container Escape (unshare)
  - T1014: eBPF Rootkit Detection

### Changed
- All security monitors use tracepoint with kprobe fallback for RHEL 9

## [1.0.5] - 2025-12-19

### Added
- Comprehensive monitoring documentation (MONITORING.md)
- Query tools and examples for log analysis
- Security event correlation examples

### Fixed
- Critical security bugs in input validation
- Improved robustness of event handling

## [1.0.4] - 2025-12-18

### Fixed
- Config file path: `linmond.conf` renamed to `linmon.conf`
- Logrotate integration: Added ExecReload to systemd service
- Repository URL in systemd service file

## [1.0.3] - 2025-12-17

### Added
- Runtime fallback from tracepoint to kprobe for RHEL 9 compatibility
- Automatic detection of blocked syscall tracepoints

### Fixed
- BPF verifier infinite loop on RHEL 9 (kernel 5.14)
- Manual loop unrolling for CIDR filtering

## [1.0.2] - 2025-12-16

### Fixed
- Disabled problematic syscall tracepoints on RHEL 9
- File and privilege monitoring graceful degradation

## [1.0.1] - 2025-12-15

### Fixed
- RHEL/Rocky Linux compatibility: correct group name detection
- Debian uses `nogroup`, RHEL uses `nobody` for group

## [1.0.0] - 2025-12-15

### Added
- Initial release of LinMon
- eBPF-based system monitoring for Linux
- Process execution and exit monitoring
- File operation monitoring (create, modify, delete)
- TCP/UDP network monitoring with IPv4/IPv6 support
- Privilege escalation detection (setuid, setgid, sudo)
- UID/GID filtering with configurable ranges
- TTY requirement for interactive session focus
- Thread filtering to reduce noise
- Rate limiting (token bucket algorithm)
- CIDR network filtering
- Process name whitelist/blacklist
- Sensitive data redaction (passwords, tokens, API keys)
- Username resolution with caching
- SHA256 binary hashing
- JSON logging format
- Systemd service integration
- SIGHUP config reload support

[Unreleased]: https://github.com/espegro/linmon/compare/v1.4.2...HEAD
[1.4.2]: https://github.com/espegro/linmon/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/espegro/linmon/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/espegro/linmon/compare/v1.3.3...v1.4.0
[1.3.3]: https://github.com/espegro/linmon/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/espegro/linmon/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/espegro/linmon/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/espegro/linmon/compare/v1.2.7...v1.3.0
[1.2.7]: https://github.com/espegro/linmon/compare/v1.2.6...v1.2.7
[1.2.6]: https://github.com/espegro/linmon/compare/v1.2.5...v1.2.6
[1.2.5]: https://github.com/espegro/linmon/compare/v1.2.4...v1.2.5
[1.2.4]: https://github.com/espegro/linmon/compare/v1.2.3...v1.2.4
[1.2.3]: https://github.com/espegro/linmon/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/espegro/linmon/compare/v1.1.2...v1.2.2
[1.1.2]: https://github.com/espegro/linmon/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/espegro/linmon/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/espegro/linmon/compare/v1.0.17...v1.1.0
[1.0.17]: https://github.com/espegro/linmon/compare/v1.0.16...v1.0.17
[1.0.16]: https://github.com/espegro/linmon/compare/v1.0.15...v1.0.16
[1.0.15]: https://github.com/espegro/linmon/compare/v1.0.14...v1.0.15
[1.0.14]: https://github.com/espegro/linmon/compare/v1.0.13...v1.0.14
[1.0.13]: https://github.com/espegro/linmon/compare/v1.0.12...v1.0.13
[1.0.12]: https://github.com/espegro/linmon/compare/v1.0.11...v1.0.12
[1.0.11]: https://github.com/espegro/linmon/compare/v1.0.10...v1.0.11
[1.0.10]: https://github.com/espegro/linmon/compare/v1.0.9...v1.0.10
[1.0.9]: https://github.com/espegro/linmon/compare/v1.0.8...v1.0.9
[1.0.8]: https://github.com/espegro/linmon/compare/v1.0.7...v1.0.8
[1.0.7]: https://github.com/espegro/linmon/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/espegro/linmon/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/espegro/linmon/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/espegro/linmon/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/espegro/linmon/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/espegro/linmon/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/espegro/linmon/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/espegro/linmon/releases/tag/v1.0.0
