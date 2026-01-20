# LinMon Security Scripts

This directory contains **core hardening scripts** that work without external dependencies (except standard security tools like AppArmor/SELinux).

For **optional** rootkit prevention features (LKRG integration), see **[extras/lkrg/README.md](../extras/lkrg/README.md)**.

## Scripts

### `linmon-report.sh`

**Purpose**: Generate human-readable activity reports from LinMon JSON event logs.

**What it does**:
1. Parses LinMon JSON events into readable summaries
2. Shows statistics by event type and user
3. Highlights security events (PTRACE, MEMFD, credential access, etc.)
4. Filters by time, user, or event type
5. Supports multiple output formats (text, JSON, CSV)

**Usage**:
```bash
# Summary of all activity
sudo ./scripts/linmon-report.sh

# Security events from last hour
sudo ./scripts/linmon-report.sh --time 60 --security-only

# Network activity for specific user
sudo ./scripts/linmon-report.sh --user alice --event net_connect_tcp

# Recent process executions (newest first)
sudo ./scripts/linmon-report.sh --event process_exec --limit 20 --reverse
```

**Requirements**:
- Root access (to read `/var/log/linmon/events.json`)
- `jq` installed (`sudo apt-get install jq`)

---

### `linmon-watchdog.sh` (Optional)

**Purpose**: Health monitoring for LinMon daemon - detects failures systemd restart alone cannot catch.

**What it detects**:
- Service crashes or stops
- Process hangs (deadlock)
- No events logged (eBPF programs unloaded)
- Immutable flags removed (tampering)
- Binary modified (rootkit replacement)
- Excessive memory usage

**When to use**:
- ✅ Production servers
- ✅ Security-critical systems
- ✅ Air-gapped environments
- ❌ Dev/test systems (overkill)

**Installation** (optional):
```bash
# Install script
sudo install -m 755 scripts/linmon-watchdog.sh /usr/local/bin/linmon-watchdog.sh

# Install systemd timer (runs every 5 minutes)
sudo install -m 644 linmon-watchdog.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now linmon-watchdog.timer

# Watch for alerts
journalctl -u linmon-watchdog -f
```

**Manual check**:
```bash
sudo /usr/local/bin/linmon-watchdog.sh
```

**See**: [WATCHDOG.md](WATCHDOG.md) for full documentation.

---

**Example output**:
```
Event Type Summary
==================
   1234  process_exec
    456  net_connect_tcp
     89  priv_setuid
     12  security_ptrace

Security Events
===============
[14:23:45] PTRACE: alice (PID 12345) attached to PID 6789
[14:25:12] CRED_READ: bob (PID 23456) accessed: /etc/shadow
```

---

### `harden-system.sh`

**Purpose**: Implements multi-layer defense against kernel rootkits using standard Linux security features.

**What it does**:
1. Verifies Secure Boot status
2. Enables kernel lockdown mode
3. Creates AppArmor/SELinux policies to restrict `insmod`/`modprobe`
4. Installs and configures AIDE (file integrity monitoring)
5. Configures LinMon for early boot (before rootkits can load)
6. *Optionally* installs LKRG if available (see note below)

**Usage**:
```bash
sudo ./scripts/harden-system.sh
```

**Requirements**:
- Root access
- Ubuntu 24.04 / RHEL 9 / Rocky Linux 9
- Reboot recommended after running

**Expected output**:
```
Protection Score: 4-5/6 layers active
System is well-protected against rootkits like Singularity
```

**Note on LKRG**: This script will attempt to install LKRG if available, but it's **optional**. Core hardening (Secure Boot, Lockdown, AppArmor, AIDE) works without LKRG. For dedicated LKRG configuration scripts, see **[extras/lkrg/](../extras/lkrg/)**.

---

### `test-rootkit-defenses.sh`

**Purpose**: Tests your system's defenses against Singularity-type attacks.

**What it tests**:
1. Unsigned module loading prevention
2. Untrusted path blocking (`/tmp`, `/dev/shm`)
3. Kernel memory access protection (`/dev/mem`)
4. LKRG configuration and status
5. AIDE file integrity detection
6. Secure Boot status
7. Kernel lockdown mode
8. LinMon event detection and boot priority

**Usage**:
```bash
sudo ./scripts/test-rootkit-defenses.sh
```

**Expected output** (well-protected system):
```
Tests Passed: 10 / 10 (100%)
System has STRONG rootkit protection
```

**Example failure detection**:
```
[TEST] Attempting to load unsigned module from /tmp...
[PASS] ✓ System BLOCKED unsigned module loading
  → Blocked by: Kernel module signature verification
```

---

## Quick Start

### 1. Harden your system

```bash
# Run core hardening script
sudo ./scripts/harden-system.sh

# Reboot to activate all protections
sudo reboot

# Optional: Configure LKRG lockdown (requires LKRG installed)
# See extras/lkrg/README.md for LKRG integration
```

### 2. Verify protections

```bash
# Test defenses
sudo ./scripts/test-rootkit-defenses.sh

# Expected: High pass rate (>80%)
```

### 3. Simulate Singularity attack

```bash
# Try to load a fake rootkit
echo "test" > /tmp/fake_rootkit.ko
sudo insmod /tmp/fake_rootkit.ko

# Expected error (one of):
# - insmod: ERROR: Required key not available (Secure Boot)
# - insmod: ERROR: Permission denied (AppArmor)
# - insmod: ERROR: Operation not permitted (LKRG/Lockdown)
```

---

## Defense Layers Explained

| Layer | Tool | Blocks | Detection | Required |
|-------|------|--------|-----------|----------|
| **1. Boot Integrity** | Secure Boot | Unsigned modules | ✓ At load time | Recommended |
| **2. Kernel Lockdown** | lockdown=confidentiality | `/dev/mem`, unsigned modules | ✓ At runtime | **Core** |
| **3. Runtime Guard** | LKRG (optional) | Hidden modules, privilege escalation | ✓ Periodic checks | Optional* |
| **4. Access Control** | AppArmor/SELinux | Loading from `/tmp`, `/dev/shm` | ✓ At load time | **Core** |
| **5. File Integrity** | AIDE | New `.ko` files | ✓ Daily scans | **Core** |
| **6. Event Monitoring** | LinMon | All activity (even if bypassed) | ✓ Real-time | **Core** |

\* **LKRG is optional** - provides additional runtime protection. See **[extras/lkrg/](../extras/lkrg/)** for installation and configuration.

---

## How Singularity is Blocked

### Attack Flow WITHOUT Hardening:
```
Attacker → insmod singularity.ko → ✓ Loads successfully
         → Hooks syscalls via ftrace → ✓ Succeeds
         → Hides from lsmod → ✓ Undetected
         → kill -59 $$ (root) → ✓ Privilege escalation
         → ICMP reverse shell → ✓ Remote access
```

### Attack Flow WITH Hardening:
```
Attacker → insmod singularity.ko → ✗ BLOCKED by Secure Boot
                                    (signature verification failed)

If Secure Boot bypassed:
Attacker → insmod singularity.ko → ✗ BLOCKED by AppArmor
                                    (untrusted path /tmp/)

If AppArmor bypassed:
Attacker → insmod singularity.ko → ✗ BLOCKED by LKRG
                                    (module loading blocked after boot)

If module loads:
Attacker → Hides from lsmod → ⚠ DETECTED by LKRG
                               (hidden module found in memory)

Attacker → kill -59 $$ (root) → ⚠ DETECTED by LKRG + LinMon
                                 (unauthorized credential change)

Attacker → ICMP trigger → ⚠ LOGGED by LinMon
                           (network events, process execution)
```

---

## Maintenance

### Daily Checks

```bash
# Check LKRG status (if installed - optional)
lsmod | grep lkrg
# See extras/lkrg/README.md for LKRG-specific checks

# Run AIDE integrity check
sudo aide --check

# Review LinMon activity (new!)
sudo ./scripts/linmon-report.sh --time 1440  # Last 24 hours
sudo ./scripts/linmon-report.sh --security-only  # Security events only

# Review LinMon logs (raw)
sudo journalctl -u linmond --since "24 hours ago"
tail -f /var/log/linmon/events.json
```

### After Kernel Updates

```bash
# Rebuild LKRG for new kernel (if using LKRG - optional)
sudo dkms autoinstall
# See extras/lkrg/README.md for LKRG maintenance

# Update AIDE baseline
sudo aide --update
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Restart LinMon
sudo systemctl restart linmond
```

### Allowing Legitimate Modules

See **[extras/lkrg/README.md](../extras/lkrg/README.md)** for LKRG-specific procedures (optional).

For core hardening:
```bash
# Update AIDE baseline after loading trusted modules
sudo aide --update
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

---

## Troubleshooting

### "LKRG not found"

LKRG is **optional**. See **[extras/lkrg/README.md](../extras/lkrg/README.md)** for installation instructions.

Core hardening works without LKRG using Secure Boot, Lockdown, AppArmor, and AIDE.

### "Secure Boot not available"

Your system may not support Secure Boot:
- Check UEFI/BIOS settings
- Legacy BIOS systems don't support Secure Boot
- VMs may need Secure Boot enabled in hypervisor

### "AppArmor profile fails to load"

```bash
# Check AppArmor status
sudo aa-status

# Reload profile
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.insmod

# Check for errors
sudo journalctl -u apparmor --since "1 hour ago"
```

### "AIDE taking too long"

AIDE initial scan can take 10-30 minutes on large systems:

```bash
# Run in background
sudo aideinit &

# Monitor progress
watch -n 5 'ps aux | grep aide'
```

---

## References

### Core Documentation
- **Full documentation**: `docs/ROOTKIT_PREVENTION.md`
- **AIDE manual**: `man aide`
- **AppArmor**: https://apparmor.net/
- **Kernel Lockdown**: https://www.kernel.org/doc/html/latest/security/lockdown.html

### Optional Features
- **LKRG integration**: `extras/lkrg/README.md` (optional rootkit prevention)
- **LKRG project**: https://lkrg.org/

---

## Security Note

These scripts implement **prevention** (blocking rootkits from loading) and **detection** (finding rootkits that do load).

**No defense is perfect**. Use defense-in-depth:
- ✅ Secure Boot + Lockdown (prevent loading)
- ✅ LKRG (detect runtime modifications)
- ✅ AppArmor/SELinux (restrict operations)
- ✅ AIDE (detect file changes)
- ✅ LinMon (log all activity)
- ✅ Network IDS (detect C2 traffic)

**Always test in a VM first** before deploying to production systems.
