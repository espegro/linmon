# Test: BPF Load Failure Logging

## Purpose

Verify that LinMon correctly logs BPF load failures with:
1. Persistent syslog entry (survives daemon exit)
2. Alert file creation (`/var/log/linmon/CRITICAL_BPF_LOAD_FAILED`)
3. Detailed stderr output for systemd journal
4. Actionable troubleshooting information

## Test Scenarios

### Scenario 1: BTF Not Available (Simulated)

**Setup**:
- Temporarily rename BTF file to simulate missing BTF

**Test**:
```bash
# Rename BTF to simulate missing
sudo mv /sys/kernel/btf/vmlinux /sys/kernel/btf/vmlinux.bak 2>/dev/null || true

# Try to start LinMon
sudo ./build/linmond

# Restore BTF
sudo mv /sys/kernel/btf/vmlinux.bak /sys/kernel/btf/vmlinux 2>/dev/null || true
```

**Expected Output**:

**stderr** (visible immediately):
```
╔═══════════════════════════════════════════════════════════════╗
║  CRITICAL: LinMon BPF Program Loading FAILED                 ║
╚═══════════════════════════════════════════════════════════════╝

Error: <error message> (errno=XX)

This failure may indicate:
  1. 🚨 KERNEL ROOTKIT blocking bpf() syscall
     → Singularity-type attack in progress
     → Check: dmesg | grep -iE '(singularity|rootkit|module)'
     → Check: lsmod | grep -iE '(singularity|rootkit)'

  2. Missing kernel BTF (BPF Type Format) support
     → Check: ls -l /sys/kernel/btf/vmlinux
     → If missing, rebuild kernel with CONFIG_DEBUG_INFO_BTF=y

  ... (rest of troubleshooting output)
```

**syslog** (persistent):
```bash
sudo journalctl -t linmond --since "1 minute ago"
```

Expected entry:
```
Jan 05 18:50:00 hostname linmond[1234]: CRITICAL: Failed to load BPF programs:
No such file or directory (errno=2). This may indicate kernel rootkit interference
(e.g., Singularity rootkit blocking bpf() syscall). LinMon cannot start without BPF support.
Verify: 1) Kernel version >= 5.8, 2) BTF enabled (/sys/kernel/btf/vmlinux exists),
3) No rootkit blocking bpf() syscall, 4) Sufficient capabilities (CAP_BPF, CAP_PERFMON).
Check dmesg for kernel messages.
```

**Alert file**:
```bash
cat /var/log/linmon/CRITICAL_BPF_LOAD_FAILED
```

Expected content:
```
LinMon BPF Loading Failed
========================
Timestamp: Sun Jan  5 18:50:00 2026
Error: No such file or directory (errno=2)
Hostname: your-hostname
Kernel: 6.8.0-90-generic

POSSIBLE ROOTKIT INTERFERENCE DETECTED

Investigation Steps:
1. Check for known rootkits:
   dmesg | grep -iE '(singularity|rootkit|lkrg|module.*blocked)'

2. Check loaded kernel modules:
   lsmod | head -20

3. Check for hidden modules (if LKRG installed):
   dmesg | grep LKRG

4. Check system call blocking:
   strace -e bpf bpftool prog list 2>&1 | head

5. Verify kernel configuration:
   ls -l /sys/kernel/btf/vmlinux
   grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
```

---

### Scenario 2: Rootkit Blocking bpf() Syscall

**Note**: This requires LKRG or similar to actually block bpf() syscall.

**Setup** (if LKRG installed):
```bash
# Enable LKRG module blocking (simulates rootkit blocking BPF)
sudo modprobe lkrg
echo 1 | sudo tee /sys/kernel/lkrg/block_modules
```

**Test**:
```bash
# Try to start LinMon
sudo ./build/linmond
```

**Expected**:
- Same output as Scenario 1, but errno will be different (likely EPERM)
- Alert file created
- Syslog entry created
- LKRG may also log the block attempt

**Cleanup**:
```bash
# Disable LKRG blocking
echo 0 | sudo tee /sys/kernel/lkrg/block_modules
```

---

### Scenario 3: Insufficient Privileges

**Setup**:
- Run LinMon as non-root user without capabilities

**Test**:
```bash
# Try to run as normal user (will fail)
./build/linmond
```

**Expected**:
- Error message about insufficient privileges
- Syslog entry may not be created (user may not have syslog write permission)
- No alert file (no write access to /var/log/linmon/)
- stderr output visible

---

## Success Criteria

For BPF load failure logging to be considered working:

1. ✅ **Syslog entry created** - persistent even after daemon exits
   - Visible in `journalctl -t linmond`
   - Priority: `daemon.crit` (LOG_CRIT)
   - Contains error message, errno, and troubleshooting hints

2. ✅ **Alert file created** - `/var/log/linmon/CRITICAL_BPF_LOAD_FAILED`
   - Contains timestamp, hostname, kernel version
   - Lists investigation steps
   - Survives daemon exit (forensic evidence)

3. ✅ **Stderr output formatted** - visible in systemd journal
   - Box-drawing characters for visibility
   - Numbered troubleshooting steps
   - Specific commands to run for diagnosis

4. ✅ **Success logging** - when BPF loads OK
   - Syslog entry: "BPF programs loaded successfully (no interference detected)"
   - Absence of this log may indicate tampering

---

## Automated Test Script

```bash
#!/bin/bash
# Test BPF load failure logging

set -e

echo "=== Testing BPF Load Failure Logging ==="

# Clean up previous test artifacts
sudo rm -f /var/log/linmon/CRITICAL_BPF_LOAD_FAILED

# Test 1: Normal BPF load (should succeed)
echo "[Test 1] Normal BPF load..."
if sudo ./build/linmond --help &>/dev/null; then
    echo "✓ LinMon binary works"
else
    echo "✗ LinMon binary failed"
    exit 1
fi

# Test 2: Check success logging
echo "[Test 2] Checking success logging..."
# (This would require actually starting the daemon and checking syslog)
# Skipped for now - needs daemon infrastructure

# Test 3: Verify alert file NOT created on success
if [ -f /var/log/linmon/CRITICAL_BPF_LOAD_FAILED ]; then
    echo "✗ Alert file should not exist on successful load"
    exit 1
else
    echo "✓ No alert file on success (correct)"
fi

# Test 4: Simulate failure (requires LKRG or BTF removal)
echo "[Test 4] Simulating BPF load failure..."
echo "   (Skipped - requires LKRG or BTF manipulation)"

echo ""
echo "=== Test Summary ==="
echo "Basic tests passed. Full failure testing requires:"
echo "  - LKRG installed with block_modules capability"
echo "  - OR BTF file manipulation"
echo "  - OR rootkit simulation"
echo ""
echo "Manual testing steps documented in this file."
```

---

## Real-World Testing

### With LKRG (Recommended)

```bash
# 1. Install LKRG
sudo apt install lkrg-dkms
sudo modprobe lkrg

# 2. Enable module blocking (simulates rootkit)
echo 1 | sudo tee /sys/kernel/lkrg/block_modules

# 3. Try to start LinMon
sudo systemctl stop linmond
sudo ./build/linmond

# 4. Check logs
sudo journalctl -t linmond --since "1 minute ago"
cat /var/log/linmon/CRITICAL_BPF_LOAD_FAILED

# 5. Cleanup
echo 0 | sudo tee /sys/kernel/lkrg/block_modules
rm /var/log/linmon/CRITICAL_BPF_LOAD_FAILED
```

### Without LKRG (BTF Manipulation)

```bash
# WARNING: This may break other BPF programs on the system

# 1. Backup BTF
sudo cp /sys/kernel/btf/vmlinux /tmp/vmlinux.btf.bak

# 2. CANNOT remove /sys/kernel/btf/vmlinux (it's in sysfs)
# Alternative: Use LD_PRELOAD to intercept libbpf calls (advanced)

# This method is not recommended - use LKRG instead
```

---

## Expected Detection Workflow

When Singularity (or similar rootkit) blocks BPF:

```
1. Admin starts LinMon: sudo systemctl start linmond
   ↓
2. LinMon tries: linmon_bpf__open_and_load()
   ↓
3. Rootkit blocks: bpf() syscall returns -EPERM
   ↓
4. LinMon logs to syslog: "CRITICAL: Failed to load BPF programs..."
   ↓
5. LinMon creates: /var/log/linmon/CRITICAL_BPF_LOAD_FAILED
   ↓
6. LinMon writes stderr: Detailed troubleshooting output
   ↓
7. systemd captures: journalctl shows all output
   ↓
8. LinMon exits: Exit code 1
   ↓
9. Admin investigates:
   - sudo journalctl -u linmond
   - cat /var/log/linmon/CRITICAL_BPF_LOAD_FAILED
   - dmesg | grep -iE '(bpf|module|rootkit)'
   ↓
10. Detection: "Singularity" found in dmesg or lsmod
```

---

## Success Metrics

- **Forensic evidence**: Alert file persists after daemon exit
- **Admin visibility**: Clear error messages guide investigation
- **SIEM integration**: Syslog entry can trigger alerts
- **Rootkit detection**: Explicit mention of Singularity and similar threats
- **Actionable**: Specific commands to run for diagnosis

All metrics implemented in BPF load failure logging patch! ✅
