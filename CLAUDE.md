# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LinMon is a Linux activity monitoring service similar to Sysmon for Windows. It uses eBPF (Extended Berkeley Packet Filter) to instrument the Linux kernel with minimal overhead, focusing on logging interactive user activity on Ubuntu and RHEL systems.

## Architecture

### Two-Component Design

1. **eBPF Programs** (`bpf/` directory)
   - Kernel-space programs written in restricted C
   - Compiled to BPF bytecode using Clang
   - Use CO-RE (Compile Once - Run Everywhere) for portability across kernel versions
   - Attach to kernel tracepoints and kprobes to capture events
   - Send events to userspace via BPF ring buffers

2. **Userspace Daemon** (`src/` directory)
   - Loads eBPF programs into the kernel using libbpf
   - Polls ring buffers for events
   - Formats and logs events as JSON to `/var/log/linmon/events.json`
   - Runs as a systemd service

### Key Files

**eBPF (kernel-space)**:
- `bpf/common.h` - Shared data structures between kernel and userspace (event types, process_event, file_event, etc.)
- `bpf/linmon.bpf.c` - Consolidated eBPF program for all monitoring (process, file, network, privileges)
- `bpf/vmlinux.h` - Kernel type definitions (should be generated with `bpftool btf dump`)

**Userspace daemon**:
- `src/main.c` - Daemon entry point, eBPF loading, event loop, and privilege dropping
- `src/logger.c` - Event logging to JSON files with wall-clock timestamps
- `src/config.c` - Configuration file parsing (`/etc/linmon/linmon.conf`)
- `src/filter.c` - Process name filtering and sensitive data redaction
- `src/userdb.c` - UID→username resolution with caching
- `src/filehash.c` - SHA256 hashing of executed binaries
- `src/procfs.c` - Reading from `/proc` (command-line arguments, environment)
- `src/pkgcache.c` - Package verification cache (dpkg/rpm) for binary trust checking

### Event Flow

```
Kernel Event → eBPF Program (UID filter, TTY check, rate limiting, CIDR filtering)
                    ↓
                Ring Buffer
                    ↓
            Userspace Daemon (process name filter, redaction, username lookup, file hashing)
                    ↓
                JSON Log
```

### Process Name Enrichment

LinMon adds a `process_name` field to events containing the basename of the executable. Implementation varies by event type:

**Process Events** (`process_exec`, `process_exit`):
- `filename` field captured in eBPF from `task_struct->mm->exe_file`
- `process_name` extracted in userspace via `strrchr(filename, '/')`
- **Always available** - captured at execution time before process can exit

**Network, Privilege, Security Events**:
- eBPF does not capture `filename` (performance optimization - avoids expensive dereferences on hot paths)
- Userspace uses `readlink()` on `/proc/<pid>/exe` symlink to get actual executable path
- `process_name` extracted from exe path basename
- **Best-effort availability** - may fail if:
  - `/proc` mounted with `hidepid` option (restricts visibility)
  - Process already terminated when event is logged
  - SELinux/AppArmor blocks `/proc` access

**Implementation** (`src/logger.c:get_process_name_from_proc()`):
- Uses `readlink()` on `/proc/<pid>/exe` symlink (no CAP_SYS_PTRACE needed - only symlink read permission)
- Gets actual executable path (not argv[0] which can be manipulated)
- Extracts basename using `strrchr()`
- Returns false on any failure → field omitted from JSON
- Fail-safe: Events logged without `process_name` if unavailable

**Startup Check** (`src/main.c`):
- Tests `/proc/1/cmdline` access at daemon startup
- Warns if inaccessible (hidepid detection)
- Does not prevent startup - best-effort approach

### Monitoring Capabilities

LinMon monitors multiple event types:

1. **Process Events**: Execution (`EVENT_PROCESS_EXEC`) and termination (`EVENT_PROCESS_EXIT`)
2. **File Events**: Create, modify, delete operations
3. **Network Events**: TCP connections (`EVENT_NET_CONNECT_TCP`, `EVENT_NET_ACCEPT_TCP`), UDP traffic
4. **Privilege Events**: `setuid`, `setgid`, sudo usage

All events can be selectively enabled/disabled via configuration file.

### Filtering Architecture

LinMon uses a **multi-layer filtering approach** for performance:

1. **Kernel-space (eBPF)**: Fast filtering before events leave the kernel
   - **TTY check**: Only processes with controlling TTY (configurable via `require_tty`)
   - **UID range**: Configured via BPF map (`min_uid`, `max_uid`)
   - **Thread filtering**: Skip thread events, only log main processes (configurable via `ignore_threads`)
   - **Rate limiting**: Token bucket algorithm (50 burst, 200 events/sec per UID) to prevent flooding
   - **CIDR filtering**: Skip network events to/from ignored IP ranges (e.g., `127.0.0.0/8`)
   - **Sudo tracking**: Scans process environment for SUDO_UID to track user across privilege escalation
   - Exit early to minimize overhead

2. **Userspace**: Rich filtering and processing
   - **Process name whitelist/blacklist**: `only_processes` or `ignore_processes`
   - **Sensitive data redaction**: Detects and redacts passwords, tokens, API keys from command lines
   - **Username resolution**: Translates UID→username with caching (`userdb.c`)
   - **File hashing**: SHA256 hash of executed binaries (optional, via `hash_binaries`)
   - **JSON formatting**: Structured logging with timestamps

## Build System

### Build Commands

```bash
# Full build
make

# Clean build artifacts
make clean

# Install as systemd service
sudo make install

# Uninstall
sudo make uninstall
```

### Build Process

1. **eBPF compilation**: `.bpf.c` files → `.bpf.o` (BPF bytecode)
   - Uses Clang with `-target bpf`
   - Strips debug symbols with `llvm-strip`

2. **Skeleton generation**: `.bpf.o` → `.skel.h` headers
   - Uses `bpftool gen skeleton`
   - Creates C headers with BPF program loading boilerplate
   - `bpftool` is auto-detected (Ubuntu: `/usr/lib/linux-tools/*/bpftool`, RHEL: `bpftool` in PATH)

3. **Daemon compilation**: `.c` + `.skel.h` → `linmond` binary
   - Links against libbpf, libelf, zlib, pthread, libcrypto (OpenSSL), libcap

### Generated Files

- `build/bpf/*.bpf.o` - Compiled eBPF programs
- `src/*.skel.h` - Generated BPF skeletons (gitignored)
- `build/linmond` - Final daemon binary

## Development Workflow

### Generating vmlinux.h

The `bpf/vmlinux.h` file contains kernel type definitions for CO-RE relocations. It was generated using:

```bash
/usr/lib/linux-tools/6.8.0-88-generic/bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

Note: On Ubuntu, the `bpftool` command in `/usr/sbin/bpftool` is just a wrapper script. Use the actual binary from `/usr/lib/linux-tools/*/bpftool`. The Makefile has been updated with the correct path.

### Adding New Event Types

LinMon uses a **single consolidated eBPF program** (`bpf/linmon.bpf.c`) instead of separate files. To add new event types:

1. **Define event structure** in `bpf/common.h`:
   - Add new `EVENT_TYPE_*` enum value
   - Create event struct (e.g., `struct my_event { __u32 type; __u64 timestamp; ... }`)

2. **Add eBPF handler** in `bpf/linmon.bpf.c`:
   - Use `SEC("tp/category/name")` for tracepoints or `SEC("kprobe/function")` for kprobes
   - Apply filtering (UID, TTY, rate limiting) early
   - Reserve ring buffer space with `bpf_ringbuf_reserve()`
   - Fill event struct and submit with `bpf_ringbuf_submit()`

3. **Add userspace handler** in `src/main.c`:
   - Add case in `handle_event()` switch statement
   - Add logging function in `src/logger.c` to format JSON output
   - Add configuration option in `src/config.c` if needed

4. **Rebuild**: The Makefile automatically compiles and generates skeleton

### eBPF Program Structure

The consolidated `bpf/linmon.bpf.c` file contains:
- GPL license declaration: `char LICENSE[] SEC("license") = "GPL";`
- **BPF maps**:
  - `config_map` (ARRAY): Configuration from userspace (`min_uid`, `max_uid`, `capture_cmdline`, etc.)
  - `events` (RINGBUF): Ring buffer for sending events to userspace (1MB)
  - `rate_limit_map` (LRU_HASH): Per-UID token bucket state for rate limiting
  - `ignore_networks_map` (HASH): CIDR blocks to ignore for network events
- **Helper functions**:
  - `should_monitor_uid()` - UID range filtering
  - `should_monitor_session()` - TTY requirement check
  - `should_rate_limit()` - Token bucket rate limiting
  - `should_ignore_network()` - CIDR filtering for network events
  - `read_sudo_uid()` - Scans process environment for SUDO_UID (up to 4KB, 48 chunks)
  - `fill_session_info()` - Populates session ID, process group, TTY name
- **eBPF programs**: Multiple `SEC("tp/...")` and `SEC("kprobe/...")` sections for different events
- All kernel struct access uses `BPF_CORE_READ()` macros for CO-RE portability

### BPF Map Communication

LinMon uses BPF maps for bidirectional communication:

1. **Userspace → Kernel** (`config_map`):
   - Daemon populates config at startup via `bpf_map_update_elem()`
   - eBPF programs read config to apply filters
   - Can be updated at runtime (e.g., on SIGHUP config reload)

2. **Kernel → Userspace** (`events` ring buffer):
   - eBPF programs submit events with `bpf_ringbuf_reserve()` / `bpf_ringbuf_submit()`
   - Userspace polls with `ring_buffer__poll()`
   - Callback function `handle_event()` processes each event

### Filtering Implementation

**eBPF Kernel-Space Filtering** (`bpf/linmon.bpf.c`):

1. **UID Range** - `should_monitor_uid()`: Reads `min_uid`/`max_uid` from `config_map`
2. **TTY Check** - `should_monitor_session()`: Only processes with controlling TTY (if `require_tty` enabled)
3. **Thread Filtering**: Skip thread events (pid != tgid) if `ignore_threads` enabled
4. **Rate Limiting** - `should_rate_limit()`: Token bucket (50 burst, 200 events/sec per UID)
5. **CIDR Filtering** - `should_ignore_network()`: Skip network events to/from ignored IP ranges
6. **Sudo Tracking** - `read_sudo_uid()`: Scans process environment for SUDO_UID (only for root processes)

**Userspace Filtering** (`src/filter.c`):

1. **Process Name Filtering** - `filter_should_log_process()`:
   - Whitelist: If `only_processes` is set, only log those names
   - Blacklist: Skip processes in `ignore_processes` list

2. **Sensitive Data Redaction** - `filter_redact_cmdline()`:
   - Detects patterns: `password=`, `token=`, `api_key=`, `-p`, `--password`, etc.
   - Replaces values with `****`
   - Example: `mysql -pSecretPass` → `mysql -p****`

When adding new event types:
- Add eBPF filtering for performance-critical checks (UID, rate limiting)
- Add userspace filtering for complex logic (regex, string matching, enrichment)

### Testing eBPF Programs

```bash
# Build
make

# Run daemon in foreground (requires root)
sudo ./build/linmond

# In another terminal, generate activity
ls -la
ps aux
cat /etc/passwd

# Check logs
tail -f /var/log/linmon/events.json
```

### Common Issues

**Build fails with "vmlinux.h not found"**: Generate it using bpftool (see above)

**Build fails with "bpftool not found"**:
- Ubuntu: `sudo apt-get install linux-tools-generic`
- RHEL/Rocky: `sudo dnf install bpftool`

**"Failed to load BPF object"**: Check kernel version (needs >= 5.8) and BTF support:
```bash
ls /sys/kernel/btf/vmlinux
```

**"Operation not permitted" on BPF load**: Run with sudo or install as systemd service which has necessary capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, `CAP_SYS_RESOURCE`)

**No events appearing**:
- Check UID filtering: Default `min_uid=1000` may be excluding your user
- Check TTY requirement: `require_tty=true` excludes GUI apps and background processes
- Check process filters: `ignore_processes` or `only_processes` may be too restrictive
- Check that specific monitoring is enabled: `monitor_processes=true`, `monitor_tcp=true`, etc.

**RHEL 9 compatibility issues**:
- BPF verifier may reject complex loops - use manual loop unrolling
- Syscall tracepoints may be blocked by security policy - use kprobes as fallback
- File/privilege monitoring may need to be disabled on locked-down systems

## Code Style

### eBPF Code
- Use kernel coding style (tabs, 80 columns)
- Always use `BPF_CORE_READ()` for kernel struct access (portability)
- Keep programs small (kernel verifier has complexity limits)
- Avoid loops when possible (verifier bounded loop support is limited)

### Userspace Code
- C99 standard
- Check return values from all libbpf functions
- Use `pthread_mutex_lock` for shared state (logger)
- Log errors to stderr before logger is initialized

## Security Considerations

LinMon implements defense-in-depth security. See `SECURITY.md` for full details.

### Privilege Dropping Sequence

**CRITICAL ORDER** - must be performed in this exact sequence:

1. **Load BPF programs** (requires `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, `CAP_SYS_RESOURCE`)
2. **Open log file** (requires write access to `/var/log/linmon/`)
3. **Drop UID/GID** to `nobody:nogroup` (UID/GID 65534) - requires `CAP_SETUID`/`CAP_SETGID`
4. **Drop ALL capabilities** - daemon runs with zero capabilities after this point
5. **Verify cannot regain root** - `setuid(0)` must fail

After privilege drop, daemon **cannot**:
- Load new BPF programs
- Modify system configuration
- Access files outside `/var/log/linmon/`
- Regain root privileges

### Configuration Security

- **Log path validation**: Must be absolute, no `..` (path traversal prevention)
- **Config file permissions**: Aborts if world-writable, warns if not owned by root
- **Integer overflow protection**: `strtoul()` with bounds checking for UID parsing
- **SIGHUP config reload**: Reloads config safely without restarting daemon

### eBPF Security

- eBPF programs run in kernel space and must pass the BPF verifier
- Use `bpf_probe_read_str()` and `bpf_probe_read_kernel()` for all kernel memory access
- Ring buffer events are read-only in userspace
- Rate limiting prevents flooding from malicious processes

## Runtime Configuration

LinMon supports **SIGHUP signal** for configuration reload without restarting:

```bash
# Edit config
sudo vi /etc/linmon/linmon.conf

# Reload config (if running as systemd service)
sudo systemctl reload linmond

# Or send SIGHUP directly
sudo pkill -HUP linmond
```

On SIGHUP, LinMon will:
- Reopen log file (supports log rotation)
- Reload configuration from `/etc/linmon/linmon.conf`
- Update BPF map config (`min_uid`, `max_uid`, filters, etc.)
- Continue monitoring without dropping events

## Cross-Platform Compatibility

LinMon has special handling for different Linux distributions:

### Group Name Detection

Different distros use different group names for the unprivileged user:
- **Debian/Ubuntu**: `nobody:nogroup`
- **RHEL/Rocky/CentOS/AlmaLinux**: `nobody:nobody`

The Makefile and `install.sh` auto-detect the correct group using `getent group nogroup`.

### RHEL 9 Specific Adaptations

RHEL 9 has stricter eBPF security policies:

1. **BPF Verifier**: Older verifier (kernel 5.14) doesn't support bounded loops well
   - **Solution**: Manual loop unrolling for CIDR filtering (reduced from 32 to 16 blocks)

2. **Syscall Tracepoint Blocking**: Security policy prevents attaching to some syscall tracepoints
   - **Solution**: Runtime fallback from tracepoints to kprobes (handled automatically in eBPF)
   - File and privilege monitoring may be disabled on locked-down systems

3. **BTF Support**: RHEL 9 has BTF enabled, but with older format
   - **Solution**: CO-RE handles this automatically

## Platform Support

### Ubuntu 24.04 (Recommended)
- Kernel 6.8+ with full eBPF support
- Install dependencies: `apt-get install clang llvm libelf-dev libbpf-dev linux-tools-generic libssl-dev libcap-dev`
- BTF enabled by default
- All features fully supported

### RHEL 9 / Rocky Linux 9 / AlmaLinux 9
- Kernel 5.14+ with backported eBPF features
- Install dependencies: `dnf install clang llvm elfutils-libelf-devel libbpf-devel bpftool openssl-devel libcap-devel`
- May need to enable CRB (CodeReady Builder) repo
- File/privilege monitoring may be limited due to security policies

### RHEL 10 / Rocky Linux 10
- Expected kernel 6.x+ with modern eBPF
- Same dependencies as RHEL 9
- Full feature support expected

### Kernel Requirements
- **Minimum**: Linux 5.8 for CO-RE support
- **Recommended**: Linux 5.14+ (RHEL 9) or 6.8+ (Ubuntu 24.04)
- **Required kernel config**:
  - `CONFIG_DEBUG_INFO_BTF=y` (BTF support)
  - `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y` (BPF enabled)
  - `CONFIG_BPF_JIT=y` (JIT compilation for performance)

Check BTF support: `ls /sys/kernel/btf/vmlinux` (should exist)

## Version

Current version is in the `VERSION` file. See `CHANGELOG.md` for release history.

The version is passed to the compiler via `-DLINMON_VERSION` and used in:
- `--version` output
- `daemon_start` log messages

### Known Limitations

1. **SIGHUP Limitations**:
   - SIGHUP reloads config flags in userspace
   - Does NOT reload BPF programs
   - **Full restart required** when enabling new security monitors

2. **Credential Read Detection**:
   - Only detects successful open() syscalls
   - Failed reads (permission denied) are not logged
   - This is intentional - reduces noise from failed attacks

3. **Path Traversal in Credential Detection**:
   - eBPF sees raw syscall path argument, not kernel-resolved path
   - `/etc/../etc/shadow` or symlinks to /etc/shadow bypass detection
   - Fixing requires LSM hooks or file_open tracepoints (major change)
   - Low risk: attackers rarely use redundant `/../` paths

### Config Files

- `linmon.conf` - Working config (host-specific values)
- `linmon.conf.example` - Reference with all options documented
- Keep synced: `linmon.conf` should have all sections from example

**Host-specific values** (differ from example defaults):
- `min_uid = 1000` (example: 0)
- `ignore_threads = true` (example: false)
- `ignore_networks = 192.168.0.0/16` (example: empty)

### Release Checklist

1. Update version in `src/main.c` (two places)
2. Update version in README.md examples if referenced
3. `make clean && make` - verify no errors
4. Test on target systems (Ubuntu 24.04, RHEL 9)
5. `git tag -a v1.x.x -m "Release v1.x.x: description"`
6. `git push && git push origin v1.x.x`
7. `gh release create v1.x.x --title "..." --notes "..."`
8. Update `/usr/local/sbin/linmond` and restart service

## Design Decisions

### Features Considered But Not Implemented

#### Application Whitelisting / Execution Prevention

**Idea**: Block execution of binaries not from package manager (dpkg/rpm)

**Why considered**:
- Would prevent most malware from executing
- Strong security posture for managed workstations
- Compliance requirement for some environments (PCI-DSS, HIPAA)

**Why not implemented**:
1. **Technical limitation**: eBPF cannot block exec() syscalls
   - eBPF tracepoints trigger AFTER exec has completed
   - Would require LSM BPF hooks (kernel >= 5.7, requires `CONFIG_BPF_LSM=y`)
   - LSM BPF requires CAP_SYS_ADMIN even after loading - conflicts with LinMon's privilege dropping

2. **Better alternatives exist**:
   - AppArmor (Ubuntu default) - can enforce execution policies
   - SELinux (RHEL default) - can enforce execution policies
   - Both are mature, well-tested, and designed for this purpose

3. **LinMon's role**: Detection, not prevention
   - LinMon is designed for monitoring and audit logging
   - Integration with SIEM for alerting and incident response
   - Can be used alongside AppArmor/SELinux for defense-in-depth

**Recommended approach**:
- Use AppArmor/SELinux for enforcement (blocking)
- Use LinMon for detection and audit trail
- LinMon logs package verification status in events (`"package": null` for unpackaged binaries)
- SIEM alerts on suspicious patterns
- Provides both prevention (LSM) and detection (LinMon) layers

**Example detection with LinMon**:
```json
{
  "type": "process_exec",
  "filename": "/tmp/suspicious_binary",
  "package": null,
  "sha256": "deadbeef...",
  "uid": 1000,
  "username": "alice"
}
```

This event can trigger SIEM alerts for:
- Execution of unpackaged binaries
- Binaries from suspicious locations (/tmp, /dev/shm)
- Modified package binaries (`pkg_modified: true`)

**Research notes**: Theoretical LSM policies were explored but determined to be:
- Not production-ready (would break desktop workflows)
- Require extensive testing and gradual rollout
- Better suited as separate project, not part of LinMon core
