# BPF Load Failure Logging - Test Results

## Test Date: January 5, 2026

---

## ✅ Test 1: Binary Smoke Test

**Command**:
```bash
./build/linmond --help
```

**Result**: ✅ PASS
- Binary compiled successfully
- Help output displays correctly
- No errors

---

## ✅ Test 2: Normal BPF Loading (Success Path)

**Command**:
```bash
sudo timeout 2s ./build/linmond
```

**Result**: ✅ PASS

**stdout**:
```
LinMon starting...
Configuration:
  UID range: 0-0 (0=unlimited)
  Require TTY: no (all sessions)
  ... (full config output)

Attaching BPF programs...
  ✓ Process exec monitoring
  ✓ Process exit monitoring
  ... (22 programs total)

Attachment summary: 22 programs attached (all features available)
✓ Dropped to UID/GID 65534 (nobody), cleared supplementary groups
✓ Dropped all capabilities (running with minimal privileges)

Monitoring active. Press Ctrl-C to exit, SIGHUP to reload config.
```

**syslog** (verified):
```bash
$ sudo journalctl -t linmond --since "1 minute ago" --no-pager
Jan 05 18:51:40 marge linmond[584628]: BPF programs loaded successfully (no interference detected)
```

✅ **Success logging works perfectly**
- `LOG_INFO` syslog entry created
- Message: "BPF programs loaded successfully (no interference detected)"
- Visible in journalctl
- Persistent across daemon exit

---

## ⏸️ Test 3: BPF Load Failure (Failure Path)

**Limitation**: Cannot test realistically without LKRG or kernel rootkit

**LKRG availability**:
```bash
$ apt-cache search lkrg
(no results)
```

LKRG is not available in default Ubuntu 24.04 repos. Would need to:
- Install from source: https://github.com/lkrg-org/lkrg
- OR use actual rootkit (not recommended on dev machine)

**Alternative testing attempted**:
- ❌ Drop CAP_BPF with capsh: Hung (incompatibility issue)
- ❌ Run as non-root: Failed on RLIMIT_MEMLOCK before BPF load
- ❌ Remove BTF file: Cannot remove sysfs entry

**Code Inspection - Failure Path Implemented**:

Verified in `src/main.c` (lines 939-1038):

1. ✅ **Error capture**: `int bpf_errno = errno; const char *error_msg = strerror(bpf_errno);`

2. ✅ **Syslog logging** (line 946-953):
```c
syslog(LOG_CRIT,
       "CRITICAL: Failed to load BPF programs: %s (errno=%d). "
       "This may indicate kernel rootkit interference (e.g., Singularity rootkit blocking bpf() syscall). "
       "LinMon cannot start without BPF support. "
       "Verify: 1) Kernel version >= 5.8, 2) BTF enabled (/sys/kernel/btf/vmlinux exists), "
       "3) No rootkit blocking bpf() syscall, 4) Sufficient capabilities (CAP_BPF, CAP_PERFMON). "
       "Check dmesg for kernel messages.",
       error_msg, bpf_errno);
```

3. ✅ **Detailed stderr output** (lines 956-986):
   - Box-drawing characters for visibility
   - 4 troubleshooting scenarios
   - Specific investigation commands
   - Mentions "Singularity" explicitly

4. ✅ **Alert file creation** (lines 990-1038):
   - Path: `/var/log/linmon/CRITICAL_BPF_LOAD_FAILED`
   - Contains timestamp, hostname (via `gethostname()`), kernel version (via `uname()`)
   - 5 investigation steps with commands
   - Persists after daemon exit

5. ✅ **Graceful exit**: `err = -1; goto cleanup;`

---

## 📋 Manual Testing Procedure (Requires LKRG)

For complete testing, install LKRG:

```bash
# Option 1: From source
git clone https://github.com/lkrg-org/lkrg
cd lkrg
make
sudo make install
sudo modprobe lkrg

# Option 2: From EPEL (RHEL/Rocky)
sudo dnf install lkrg

# Test BPF blocking
echo 1 | sudo tee /sys/kernel/lkrg/block_modules
sudo ./build/linmond

# Expected: BPF load failure with full logging
# Verify:
sudo journalctl -t linmond --since "1 minute ago"
cat /var/log/linmon/CRITICAL_BPF_LOAD_FAILED

# Cleanup
echo 0 | sudo tee /sys/kernel/lkrg/block_modules
rm /var/log/linmon/CRITICAL_BPF_LOAD_FAILED
```

---

## Expected Output (Based on Code Inspection)

### When BPF load fails:

**stderr**:
```
╔═══════════════════════════════════════════════════════════════╗
║  CRITICAL: LinMon BPF Program Loading FAILED                 ║
╚═══════════════════════════════════════════════════════════════╝

Error: Operation not permitted (errno=1)

This failure may indicate:
  1. 🚨 KERNEL ROOTKIT blocking bpf() syscall
     → Singularity-type attack in progress
     → Check: dmesg | grep -iE '(singularity|rootkit|module)'
     → Check: lsmod | grep -iE '(singularity|rootkit)'

  2. Missing kernel BTF (BPF Type Format) support
     → Check: ls -l /sys/kernel/btf/vmlinux
     → If missing, rebuild kernel with CONFIG_DEBUG_INFO_BTF=y

  3. Insufficient privileges
     → LinMon requires: CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN
     → Check: getcap /usr/local/sbin/linmond
     → Running as root? Check: id -u

  4. Kernel version too old
     → LinMon requires kernel >= 5.8 for CO-RE support
     → Check: uname -r

For rootkit investigation:
  sudo dmesg | tail -100
  sudo lsmod | head -20
  sudo journalctl -u linmond --since '10 minutes ago'
```

**syslog**:
```
Jan 05 18:55:00 hostname linmond[1234]: CRITICAL: Failed to load BPF programs: Operation not permitted (errno=1). This may indicate kernel rootkit interference (e.g., Singularity rootkit blocking bpf() syscall). LinMon cannot start without BPF support. Verify: 1) Kernel version >= 5.8, 2) BTF enabled (/sys/kernel/btf/vmlinux exists), 3) No rootkit blocking bpf() syscall, 4) Sufficient capabilities (CAP_BPF, CAP_PERFMON). Check dmesg for kernel messages.
Jan 05 18:55:00 hostname linmond[1234]: Created alert file: /var/log/linmon/CRITICAL_BPF_LOAD_FAILED
```

**Alert file** (`/var/log/linmon/CRITICAL_BPF_LOAD_FAILED`):
```
LinMon BPF Loading Failed
========================
Timestamp: Sun Jan  5 18:55:00 2026
Error: Operation not permitted (errno=1)
Hostname: marge
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

## ✅ Verification Checklist

| Test | Status | Notes |
|------|--------|-------|
| Binary builds successfully | ✅ PASS | 740K binary, version 1.3.1 |
| Normal BPF load works | ✅ PASS | 22 programs attached |
| Success logging to syslog | ✅ PASS | `BPF programs loaded successfully` |
| Success log uses LOG_INFO | ✅ PASS | Verified in journalctl |
| Failure logging code present | ✅ PASS | Lines 939-1038 in main.c |
| Syslog failure logging | ✅ CODE VERIFIED | Uses LOG_CRIT |
| Alert file creation | ✅ CODE VERIFIED | `/var/log/linmon/CRITICAL_BPF_LOAD_FAILED` |
| stderr box formatting | ✅ CODE VERIFIED | Box-drawing chars present |
| Hostname capture | ✅ CODE VERIFIED | `gethostname()` |
| Kernel version capture | ✅ CODE VERIFIED | `uname()` |
| Investigation steps | ✅ CODE VERIFIED | 5 steps with commands |
| Singularity mention | ✅ CODE VERIFIED | Explicit in error message |
| No external dependencies | ✅ PASS | Only stdlib, syslog, uname |
| Real failure testing | ⏸️ BLOCKED | Requires LKRG installation |

---

## 🎯 Summary

### What Works (Verified):
- ✅ Binary compilation
- ✅ Normal BPF loading
- ✅ Success logging to syslog
- ✅ All failure logging code implemented

### What Cannot Be Tested (Requires LKRG):
- ⏸️ Actual BPF load failure scenario
- ⏸️ Alert file creation in real failure
- ⏸️ Syslog CRITICAL entry in real failure

### Code Quality:
- ✅ Proper error handling (errno capture)
- ✅ Comprehensive logging (syslog + alert file + stderr)
- ✅ User-friendly output (box formatting, numbered steps)
- ✅ Forensic evidence (alert file persists)
- ✅ No external dependencies (stdlib only)
- ✅ Explicit rootkit detection hint (mentions Singularity)

---

## 📌 Recommendations

1. **For Production Testing**: Install LKRG on test VM and run full failure scenario

2. **For CI/CD**: Add unit tests that mock `linmon_bpf__open_and_load()` failure

3. **For Documentation**: Update README with BPF failure troubleshooting guide

4. **For Deployment**: Ensure `/var/log/linmon/` directory exists with write permissions

---

## ✅ Conclusion

**BPF Load Failure Logging is correctly implemented** (code inspection verified).

**Success path tested and works perfectly** (syslog entry verified).

**Failure path cannot be fully tested** without LKRG or kernel rootkit, but code implementation is complete and correct.

**Production testing recommended** with LKRG on test VM before deployment.

---

*Test performed by: Claude Code*
*Date: January 5, 2026*
*Environment: Ubuntu 24.04, Kernel 6.8.0-90-generic*
*LinMon Version: 1.3.1*
