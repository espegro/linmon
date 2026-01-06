# Changelog

All notable changes to LinMon are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/espegro/linmon/compare/v1.1.0...HEAD
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
