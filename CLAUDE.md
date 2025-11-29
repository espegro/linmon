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

- `bpf/common.h` - Shared data structures between kernel and userspace (event types, process_event, file_event, etc.)
- `bpf/process_monitor.bpf.c` - eBPF program for process execution/exit monitoring
- `bpf/vmlinux.h` - Kernel type definitions (should be generated with `bpftool btf dump`)
- `src/main.c` - Daemon entry point, eBPF loading, and event loop
- `src/logger.c` - Event logging to JSON files with wall-clock timestamps
- `src/config.c` - Configuration file parsing
- `src/filter.c` - Process name filtering and sensitive data redaction

### Event Flow

```
Kernel Event → eBPF Program (UID filter, TTY check)
                    ↓
                Ring Buffer
                    ↓
            Userspace Daemon (process name filter, redaction)
                    ↓
                JSON Log
```

### Filtering Architecture

LinMon uses a **multi-layer filtering approach** for performance:

1. **Kernel-space (eBPF)**: Fast filtering before events leave the kernel
   - TTY check: Only processes with controlling TTY
   - UID range: Configured via BPF map (`min_uid`, `max_uid`)
   - Exit early to minimize overhead

2. **Userspace**: Rich filtering and processing
   - Process name whitelist/blacklist
   - Sensitive data redaction (passwords, tokens, API keys)
   - JSON formatting and logging

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

3. **Daemon compilation**: `.c` + `.skel.h` → `linmond` binary
   - Links against libbpf, libelf, zlib

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

### Adding New eBPF Programs

1. Create `bpf/newfeature.bpf.c` following the pattern in `process_monitor.bpf.c`
2. Define event structures in `bpf/common.h`
3. The Makefile will automatically compile it and generate `src/newfeature.skel.h`
4. Include the skeleton in `src/main.c` and attach the programs

### eBPF Program Structure

Each `.bpf.c` file should:
- Include `vmlinux.h`, `bpf/bpf_helpers.h`, `bpf/bpf_core_read.h`
- Define a GPL license: `char LICENSE[] SEC("license") = "GPL";`
- Use `SEC("tp/category/name")` or `SEC("kprobe/function")` for program sections
- Use BPF maps for communication (ring buffers, hash maps)
- Use `BPF_CORE_READ()` macros for portable kernel struct access

### Filtering Implementation

**eBPF Kernel-Space Filtering** (`bpf/process_monitor.bpf.c`):

1. **TTY Check** - `is_interactive_session()`: Only processes with controlling TTY
2. **UID Range** - `should_monitor_uid()`: Reads `min_uid`/`max_uid` from BPF `config_map`

The `config_map` is populated by userspace at startup and can be updated at runtime.

**Userspace Filtering** (`src/filter.c`):

1. **Process Name Filtering** - `filter_should_log_process()`:
   - Whitelist: If `only_processes` is set, only log those names
   - Blacklist: Skip processes in `ignore_processes` list

2. **Sensitive Data Redaction** - `filter_redact_cmdline()`:
   - Detects patterns: `password=`, `token=`, `api_key=`, `-p`, etc.
   - Replaces values with `****`
   - Example: `mysql -pSecretPass` → `mysql -p****`

When adding new event types:
- Add eBPF filtering for performance-critical checks (UID, GID)
- Add userspace filtering for complex logic (regex, string matching)

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

**"Failed to load BPF object"**: Check kernel version (needs >= 5.8) and BTF support:
```bash
ls /sys/kernel/btf/vmlinux
```

**"Operation not permitted"**: Run with sudo or install as systemd service which has necessary capabilities

**No events appearing**: Check `is_interactive_session()` logic - it may be filtering too aggressively

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

- The daemon requires `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, and `CAP_SYS_RESOURCE`
- eBPF programs run in kernel space and must pass the verifier
- Event data from kernel should be treated carefully (use `bpf_probe_read_str` for strings)
- JSON logging escapes special characters to prevent log injection

## Future Extensions

Areas for expansion:
- File monitoring eBPF program (open, read, write, unlink)
- Network connection tracking (TCP connect/accept)
- User login detection (PAM integration or utmp monitoring)
- Configuration file support (`/etc/linmon/linmon.conf`)
- Log rotation and compression
- Syslog integration
- Event filtering rules

## Platform Support

### Ubuntu (22.04+)
- Install dependencies: `apt-get install clang llvm libelf-dev libbpf-dev`
- Kernel must have BTF enabled (default in Ubuntu 20.04+)

### RHEL/Rocky/Alma (8+)
- Install dependencies: `dnf install clang llvm elfutils-libelf-devel libbpf-devel`
- May need to enable kernel-devel for headers
- RHEL 8 uses older kernel (4.18) with backported eBPF features

### Kernel Requirements
- Linux >= 5.8 for full CO-RE support
- BTF (BPF Type Format) enabled in kernel config
- CONFIG_DEBUG_INFO_BTF=y
- CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y
