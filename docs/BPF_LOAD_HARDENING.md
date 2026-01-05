# BPF Load Hardening and Post-Load Protection

This document describes LinMon's defense mechanisms when BPF loading fails (rootkit interference) and how to enable "lockdown after load" mode.

---

## Problem Statement

**Scenario 1: Singularity loads BEFORE LinMon**

```bash
# Attacker loads Singularity first
sudo insmod singularity.ko

# LinMon tries to start
sudo systemctl start linmond

# What happens:
# 1. Singularity blocks bpf() syscall
# 2. linmon_bpf__open_and_load() fails
# 3. LinMon exits with error code
# 4. NO persistent log of the failure (only stderr)
```

**Current behavior**:
- Error message: `"Failed to open/load LinMon BPF programs"` → stderr only
- Exit code: 1
- **No syslog/journal entry** ⚠️

**Scenario 2: LinMon loads FIRST, but nothing prevents other BPF programs**

```bash
# LinMon starts successfully
sudo systemctl start linmond

# LinMon's eBPF programs are loaded
# But other processes can STILL load BPF programs after LinMon

# Attacker could load Singularity's BPF programs later
```

---

## Solution 1: Enhanced BPF Load Failure Logging

### Current Code (src/main.c:934-939)

```c
// Load and open BPF application
skel = linmon_bpf__open_and_load();
if (!skel) {
    fprintf(stderr, "Failed to open/load LinMon BPF programs\n");
    err = -1;
    goto cleanup;
}
```

### Improved Code

```c
// Load and open BPF application
skel = linmon_bpf__open_and_load();
if (!skel) {
    // Get libbpf error details
    int bpf_errno = errno;
    const char *error_msg = strerror(bpf_errno);

    // CRITICAL: Log to syslog IMMEDIATELY (before cleanup)
    // This ensures we have a persistent record even if BPF loading was blocked
    openlog("linmond", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_CRIT, "CRITICAL: Failed to load BPF programs: %s (errno=%d). "
                     "This may indicate kernel rootkit interference (e.g., Singularity). "
                     "LinMon cannot start without BPF support. "
                     "Verify: 1) Kernel version >= 5.8, 2) BTF enabled (/sys/kernel/btf/vmlinux exists), "
                     "3) No rootkit blocking bpf() syscall. Check dmesg for details.",
           error_msg, bpf_errno);

    // Also log to stderr for systemd journal
    fprintf(stderr, "CRITICAL: Failed to open/load LinMon BPF programs: %s\n", error_msg);
    fprintf(stderr, "This may indicate:\n");
    fprintf(stderr, "  1. Kernel rootkit blocking bpf() syscall (Singularity-type attack)\n");
    fprintf(stderr, "  2. Missing kernel BTF support\n");
    fprintf(stderr, "  3. Insufficient privileges (need CAP_BPF, CAP_PERFMON)\n");
    fprintf(stderr, "Check: dmesg | grep -E '(bpf|LKRG|module)'\n");

    // Try to write to fallback alert file (survives even if daemon exits)
    FILE *alert_fp = fopen("/var/log/linmon/CRITICAL_BPF_LOAD_FAILED", "w");
    if (alert_fp) {
        fprintf(alert_fp, "LinMon BPF loading failed at %s\n", ctime(&daemon_start_time));
        fprintf(alert_fp, "Error: %s (errno=%d)\n", error_msg, bpf_errno);
        fprintf(alert_fp, "Possible rootkit interference detected.\n");
        fprintf(alert_fp, "Investigate: dmesg | grep -E '(bpf|module|LKRG)'\n");
        fclose(alert_fp);
    }

    err = -1;
    goto cleanup;
}

// If we get here, BPF loaded successfully
syslog(LOG_INFO, "BPF programs loaded successfully (no interference detected)");
```

### Benefits

1. ✅ **Persistent logging**: Syslog entry survives daemon exit
2. ✅ **Forensic evidence**: Alert file `/var/log/linmon/CRITICAL_BPF_LOAD_FAILED` left behind
3. ✅ **Actionable errors**: Tells admin what to check
4. ✅ **Rootkit detection hint**: Explicitly mentions Singularity-type attacks

---

## Solution 2: Lockdown After Load (LKRG Integration)

LinMon **cannot** directly enable kernel lockdown mode at runtime (it's a boot parameter). However, it **can** enable LKRG's `block_modules` feature to prevent BPF programs from loading after LinMon.

### Implementation

#### Option A: Via LKRG `block_modules` (Recommended)

After LinMon's BPF programs are loaded, enable LKRG's module blocking:

```c
// After successful BPF load (src/main.c, after line 939)
static int enable_lkrg_bpf_protection(void)
{
    // Try to enable LKRG module blocking (if LKRG is loaded)
    FILE *fp = fopen("/sys/kernel/lkrg/block_modules", "w");
    if (!fp) {
        // LKRG not loaded - not critical, but log a warning
        syslog(LOG_WARNING, "LKRG not available - cannot enable post-load BPF blocking. "
                           "Consider installing LKRG for defense-in-depth.");
        return -1;
    }

    fprintf(fp, "1");
    fclose(fp);

    syslog(LOG_INFO, "LKRG module blocking enabled - no new kernel modules can load");
    printf("  ✓ LKRG module blocking enabled (defense-in-depth)\n");
    return 0;
}

// Call this after BPF programs are attached
// In main(), after line 790 (after all BPF programs attached):
enable_lkrg_bpf_protection();
```

**What this does**:
- After LinMon's eBPF programs are loaded and attached
- Enables LKRG's `block_modules=1`
- **Prevents ANY kernel modules from loading** (including Singularity)
- Other eBPF programs can still load (LKRG doesn't block `bpf()` syscall, only `insmod`)

**Limitations**:
- Only blocks **kernel modules** (.ko files), not eBPF programs
- Singularity could still be loaded as eBPF (but most rootkits use LKM)

#### Option B: Via seccomp-bpf filter (Advanced)

LinMon could install a seccomp filter to block `bpf()` syscall for other processes:

```c
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>

static int install_bpf_syscall_filter(void)
{
    // This would block bpf() syscall for child processes
    // But LinMon doesn't spawn children, so limited utility

    // NOTE: Cannot block bpf() for OTHER processes (requires LSM or kernel module)
    // This approach is NOT effective for LinMon's use case

    return -ENOTSUP;
}
```

**Problem**: seccomp-bpf only applies to current process and children. Cannot block `bpf()` for unrelated processes.

#### Option C: Via BPF LSM hooks (Requires Kernel >= 5.7 + CONFIG_BPF_LSM=y)

```c
// Theoretical: Use BPF LSM to deny bpf() syscall after LinMon loads
// Requires: CONFIG_BPF_LSM=y in kernel config
// Not implemented in current LinMon (adds complexity, limited kernel support)
```

**Conclusion**: **Option A (LKRG integration)** is most practical.

---

## Solution 3: Systemd Watchdog for BPF Load Failures

Configure systemd to alert on LinMon startup failures:

### `/etc/systemd/system/linmond.service`

```ini
[Unit]
Description=LinMon eBPF monitoring
After=local-fs.target
OnFailure=linmon-failure-alert.service

[Service]
Type=simple
ExecStart=/usr/local/sbin/linmond
Restart=on-failure
RestartSec=5
StartLimitBurst=3
StartLimitIntervalSec=60

# Alert if LinMon fails to start 3 times in 60 seconds
[Install]
WantedBy=multi-user.target
```

### `/etc/systemd/system/linmon-failure-alert.service`

```ini
[Unit]
Description=LinMon Failure Alert

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/linmon-failure-alert.sh
```

### `/usr/local/sbin/linmon-failure-alert.sh`

```bash
#!/bin/bash
# Alert script when LinMon fails to start

# Check if BPF load failed
if [ -f /var/log/linmon/CRITICAL_BPF_LOAD_FAILED ]; then
    ALERT_MSG="CRITICAL: LinMon failed to load BPF programs - possible rootkit interference!"

    # Log to syslog
    logger -t linmon-alert -p daemon.crit "$ALERT_MSG"

    # Send email (if configured)
    if command -v mail &>/dev/null; then
        echo "$ALERT_MSG" | mail -s "SECURITY ALERT: LinMon BPF Loading Failed" root
    fi

    # Check for known rootkit indicators
    if dmesg | grep -qE "(singularity|rootkit|module.*blocked|bpf.*denied)"; then
        logger -t linmon-alert -p daemon.crit "Rootkit indicators found in dmesg"
    fi

    # Check LKRG logs
    if dmesg | grep -q LKRG; then
        dmesg | grep LKRG | tail -10 | logger -t linmon-alert -p daemon.warning
    fi
fi
```

---

## Complete Implementation Script

Create `/usr/local/sbin/linmon-enable-lockdown.sh`:

```bash
#!/bin/bash
# Enable lockdown-after-load for LinMon
set -e

echo "=== LinMon Lockdown After Load ==="

# 1. Check if LinMon is running
if ! systemctl is-active --quiet linmond; then
    echo "ERROR: LinMon is not running. Start it first: sudo systemctl start linmond"
    exit 1
fi

# 2. Check if LKRG is available
if [ ! -f /sys/kernel/lkrg/block_modules ]; then
    echo "WARNING: LKRG not loaded. Install LKRG first:"
    echo "  sudo apt install lkrg-dkms"
    exit 1
fi

# 3. Enable LKRG module blocking
echo "Enabling LKRG module blocking..."
echo 1 > /sys/kernel/lkrg/block_modules

# 4. Verify
BLOCK_STATUS=$(cat /sys/kernel/lkrg/block_modules)
if [ "$BLOCK_STATUS" = "1" ]; then
    echo "✓ LKRG module blocking ENABLED"
    logger -t linmond -p daemon.info "LKRG module blocking enabled - kernel modules locked down"
else
    echo "✗ Failed to enable LKRG module blocking"
    exit 1
fi

# 5. Make persistent
if ! grep -q "kernel.lkrg.block_modules = 1" /etc/sysctl.d/99-lkrg.conf 2>/dev/null; then
    echo "Making LKRG blocking persistent..."
    echo "kernel.lkrg.block_modules = 1" >> /etc/sysctl.d/99-lkrg.conf
    echo "✓ LKRG blocking will persist across reboots"
fi

echo ""
echo "Lockdown Status:"
echo "  LinMon: Running with BPF programs loaded"
echo "  LKRG: Module blocking enabled"
echo "  Result: No kernel modules can load (Singularity blocked)"
echo ""
echo "NOTE: To load legitimate modules, temporarily disable:"
echo "  echo 0 > /sys/kernel/lkrg/block_modules"
echo "  modprobe your_module"
echo "  echo 1 > /sys/kernel/lkrg/block_modules"
```

---

## Testing

### Test 1: BPF Load Failure Logging

Simulate Singularity blocking BPF:

```bash
# Stop LinMon
sudo systemctl stop linmond

# Temporarily block BPF syscall (simulate rootkit)
# NOTE: This requires kernel module or LSM, so for testing we'll use LKRG

# If LKRG is loaded with block_modules=1:
echo 1 > /sys/kernel/lkrg/block_modules

# Try to start LinMon (should fail to load BPF)
sudo systemctl start linmond

# Check logs
sudo journalctl -u linmond --since "1 minute ago"
# Expected: "CRITICAL: Failed to load BPF programs..."

# Check syslog
sudo grep "linmond.*CRITICAL" /var/log/syslog

# Check alert file
cat /var/log/linmon/CRITICAL_BPF_LOAD_FAILED
```

### Test 2: Lockdown After Load

```bash
# Start LinMon (with LKRG loaded)
sudo systemctl start linmond

# Enable lockdown
sudo /usr/local/sbin/linmon-enable-lockdown.sh

# Try to load a module (should fail)
sudo insmod /tmp/test.ko
# Expected: insmod: ERROR: Operation not permitted

# Verify LKRG blocked it
dmesg | tail
# Expected: LKRG: Module loading blocked
```

---

## Comparison: Before vs After

| Scenario | Before Improvements | After Improvements |
|----------|--------------------|--------------------|
| **BPF load fails** | ❌ stderr only | ✅ Syslog + alert file + email |
| **Rootkit loads first** | ❌ No forensic evidence | ✅ `/var/log/linmon/CRITICAL_BPF_LOAD_FAILED` |
| **LinMon loads, then rootkit** | ⚠️ Rootkit can load | ✅ LKRG blocks rootkit module |
| **Admin investigation** | ❌ No guidance | ✅ Explicit error messages with next steps |

---

## Recommendations

### Minimal (Logging Only)

Apply the improved BPF load failure logging:
- Patch `src/main.c` with enhanced error handling
- Ensures persistent log of BPF load failures

### Recommended (Logging + LKRG)

1. Install LKRG: `sudo apt install lkrg-dkms`
2. Apply BPF load failure logging patch
3. Configure LinMon to enable LKRG blocking after load
4. Result: Complete protection against post-load rootkits

### Maximum (All Layers)

1. Logging improvements (as above)
2. LKRG integration (as above)
3. Systemd OnFailure alerts
4. Email notifications
5. SIEM integration for real-time alerting

---

## Implementation Status

| Feature | Status | Priority |
|---------|--------|----------|
| Enhanced BPF load failure logging | 📝 Proposed | **HIGH** |
| LKRG lockdown-after-load | 📝 Proposed | MEDIUM |
| Systemd OnFailure alerts | 📝 Proposed | MEDIUM |
| BPF LSM hooks | ❌ Not planned | LOW (complex) |

---

## Conclusion

**Yes**, LinMon can:

1. ✅ **Log BPF load failures persistently** (syslog + alert file)
2. ✅ **Trigger lockdown after load via LKRG** (blocks kernel modules)
3. ⚠️ **Cannot prevent other eBPF programs** (would require LSM or kernel module)

**Recommendation**: Implement enhanced logging (high priority) + LKRG integration (medium priority) for defense-in-depth.
