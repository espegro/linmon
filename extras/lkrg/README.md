# LKRG Integration for LinMon

**Dependency**: Linux Kernel Runtime Guard (LKRG)

This directory contains optional scripts for integrating LinMon with LKRG to provide:
- Runtime module blocking after LinMon loads
- Hidden module detection
- Kernel integrity checking
- Defense-in-depth against rootkits like Singularity

---

## ⚠️ Important: Optional Feature

**LKRG is NOT required for LinMon to work.**

LinMon core functionality (eBPF monitoring, event logging, BPF failure detection) works completely standalone without LKRG.

LKRG extras provide **additional defense-in-depth** for high-security environments.

---

## What is LKRG?

**Linux Kernel Runtime Guard** is an open-source kernel module that performs runtime integrity checking of the Linux kernel.

**Project**: https://github.com/lkrg-org/lkrg
**Maintainer**: Openwall Project

### LKRG Capabilities

1. **Module Blocking**: Prevents new kernel modules from loading
2. **Hidden Module Detection**: Finds modules hidden from `lsmod`
3. **Integrity Checking**: Periodically verifies kernel structures
4. **Syscall Table Protection**: Detects syscall hooking
5. **Credential Monitoring**: Detects unauthorized privilege escalation

---

## Installation

### Ubuntu/Debian (Build from Source)

LKRG is not available in default Ubuntu repos. Build from source:

```bash
# Install dependencies
sudo apt-get install build-essential linux-headers-$(uname -r) git

# Clone LKRG
git clone https://github.com/lkrg-org/lkrg
cd lkrg

# Build and install
make
sudo make install

# Load kernel module
sudo modprobe lkrg

# Verify
lsmod | grep lkrg
```

### RHEL/Rocky/AlmaLinux (EPEL Repository)

```bash
# Enable EPEL
sudo dnf install epel-release

# Install LKRG
sudo dnf install lkrg

# Load module
sudo modprobe lkrg

# Verify
lsmod | grep lkrg
```

### Persistent Loading (Systemd)

Make LKRG load at boot:

```bash
# Create systemd service
sudo cat > /etc/modules-load.d/lkrg.conf <<EOF
lkrg
EOF

# Reboot and verify
sudo reboot
lsmod | grep lkrg
```

---

## Scripts in This Directory

### 1. `linmon-enable-lockdown.sh`

**Purpose**: Enable LKRG module blocking AFTER LinMon has loaded its eBPF programs.

**Usage**:
```bash
# Start LinMon first
sudo systemctl start linmond

# Then enable lockdown
sudo ./linmon-enable-lockdown.sh
```

**What it does**:
1. Verifies LinMon is running with BPF programs loaded
2. Checks that LKRG is installed and loaded
3. Enables LKRG `block_modules=1`
4. Makes configuration persistent across reboots

**Result**: No kernel modules can load after this point (including rootkits like Singularity).

**Output**:
```
╔═══════════════════════════════════════════════════════════╗
║    LinMon Lockdown After Load Configuration               ║
╚═══════════════════════════════════════════════════════════╝

[1/4] Checking LinMon status...
[✓] LinMon is running
[✓] LinMon BPF programs appear to be loaded

[2/4] Checking LKRG availability...
[✓] LKRG kernel module is loaded
[✓] LKRG block_modules interface available

[3/4] Enabling LKRG module blocking...
[✓] LKRG module blocking ENABLED

[4/4] Making configuration persistent...
[✓] Configuration will persist across reboots

Lockdown Status:
  ✓ LinMon:       Running with eBPF programs loaded
  ✓ LKRG:         Module blocking ENABLED
  ✓ Result:       No new kernel modules can load
```

---

### 2. `linmon-check-lockdown.sh`

**Purpose**: Check comprehensive lockdown status (both LKRG and native kernel protections).

**Usage**:
```bash
sudo ./linmon-check-lockdown.sh
```

**What it checks**:
1. LinMon daemon status and BPF programs
2. Native kernel lockdown mode (if supported)
3. LKRG status and configuration
4. Module signature enforcement (Secure Boot)
5. AppArmor/SELinux restrictions

**Output**:
```
╔═══════════════════════════════════════════════════════════╗
║         LinMon Lockdown Status Report                     ║
╚═══════════════════════════════════════════════════════════╝

[1/5] LinMon eBPF Status
[✓] LinMon daemon is running
[✓] eBPF programs appear to be loaded

[2/5] Native Kernel Lockdown Mode
[✓] Lockdown mode: CONFIDENTIALITY (maximum protection)

[3/5] LKRG Runtime Protection (Optional)
[✓] LKRG kernel module is loaded
[✓] LKRG module blocking: ENABLED
[✓] LKRG integrity checks: Every 5s (good)

[4/5] Module Signature Enforcement
[✓] Secure Boot: ENABLED

[5/5] Additional Security Controls
[✓] AppArmor: Active with insmod restrictions

Protection Score: 5 / 5 (100%)
[✓] STRONG protection against rootkits like Singularity
```

---

### 3. `setup-failure-alerting.sh`

**Purpose**: Configure systemd to alert when LinMon fails to start (e.g., BPF blocked by rootkit).

**Usage**:
```bash
sudo ./setup-failure-alerting.sh
```

**What it does**:
1. Installs `linmon-failure-alert.sh` to `/usr/local/sbin/`
2. Creates systemd service `linmon-failure-alert.service`
3. Configures LinMon with `OnFailure=linmon-failure-alert.service`
4. Sets up automatic failure detection

**How it works**:
```
LinMon fails to start
        ↓
systemd triggers: OnFailure=linmon-failure-alert.service
        ↓
linmon-failure-alert.sh runs
        ↓
Checks for: /var/log/linmon/CRITICAL_BPF_LOAD_FAILED
        ↓
Logs CRITICAL alerts to syslog
        ↓
Checks dmesg for rootkit indicators (Singularity, LKRG messages)
        ↓
Admin alerted via syslog/email (if configured)
```

**Testing**:
```bash
# After setup, test the alert
sudo systemctl stop linmond
sudo systemctl kill linmond --signal=KILL

# Check alerts
sudo journalctl -u linmon-failure-alert --since '1 minute ago'
```

---

### 4. `linmon-failure-alert.sh` (Internal)

**Purpose**: Alert handler called by systemd when LinMon fails.

**Called by**: `systemd` via `OnFailure=` (not called manually)

**What it checks**:
1. BPF load failure marker (`/var/log/linmon/CRITICAL_BPF_LOAD_FAILED`)
2. dmesg for rootkit indicators (Singularity, hidden modules)
3. LKRG logs for detection events
4. Recent LinMon errors in journal

**Alerting**:
- Logs to syslog with `daemon.crit` priority
- Creates `/var/log/linmon/SECURITY_ALERT_ACTIVE` marker
- Sends email if `MAILTO` environment variable set
- Tracks failure count for persistent attacks

---

## Usage Workflows

### Workflow 1: Enable LKRG Lockdown (Recommended)

**For systems where LKRG can be installed**:

```bash
# 1. Install LinMon (core)
cd linmon
make clean && make
sudo make install

# 2. Install LKRG
# ... (see installation section above)

# 3. Start LinMon
sudo systemctl start linmond

# 4. Enable LKRG lockdown
cd extras/lkrg
sudo ./linmon-enable-lockdown.sh

# 5. Setup failure alerting (optional)
sudo ./setup-failure-alerting.sh

# 6. Verify protection
sudo ./linmon-check-lockdown.sh
```

**Result**: LinMon monitors + LKRG blocks new kernel modules

---

### Workflow 2: Check Protection Status

**Verify current security posture**:

```bash
cd extras/lkrg
sudo ./linmon-check-lockdown.sh
```

**Use cases**:
- Verify lockdown after system updates
- Troubleshoot protection gaps
- Compliance audits (document protection layers)
- Post-incident verification

---

### Workflow 3: Disable LKRG Temporarily

**To load legitimate kernel modules**:

```bash
# 1. Disable LKRG blocking
echo 0 | sudo tee /sys/kernel/lkrg/block_modules

# 2. Load your module
sudo modprobe your_module

# 3. Re-enable LKRG blocking
echo 1 | sudo tee /sys/kernel/lkrg/block_modules

# 4. Verify
cat /sys/kernel/lkrg/block_modules
# Expected: 1
```

**Note**: LinMon continues working during this process (independent of LKRG).

---

## Rootkit Protection

### How LKRG + LinMon Blocks Singularity

**Singularity attack flow WITHOUT LKRG**:
```
1. Attacker loads Singularity: sudo insmod singularity.ko
   → ✅ Loads successfully (if LinMon not running)

2. Singularity hooks syscalls via ftrace
   → ✅ Succeeds

3. Singularity blocks bpf() syscall
   → ✅ Succeeds

4. Admin tries to start LinMon: sudo systemctl start linmond
   → ❌ BPF load fails (blocked by Singularity)
   → ✅ LinMon logs CRITICAL alert (new feature!)
```

**Singularity attack flow WITH LinMon + LKRG**:
```
1. LinMon starts early at boot
   → ✅ eBPF programs loaded successfully

2. LKRG lockdown enabled
   → ✅ block_modules=1 active

3. Attacker tries to load Singularity: sudo insmod singularity.ko
   → ❌ BLOCKED by LKRG
   → dmesg: "LKRG: Module loading blocked (block_modules=1)"

4. Even if attacker bypasses LKRG somehow...
   → LinMon already monitoring (eBPF programs active)
   → Singularity would be detected by LinMon's module monitoring
```

---

## Limitations

### What LKRG Cannot Do

1. **Cannot block eBPF programs**: LKRG blocks kernel modules (.ko files), not eBPF programs loaded via `bpf()` syscall

2. **Cannot detect all ftrace hooks**: ftrace is a legitimate kernel feature, LKRG may not flag all ftrace-based hooks

3. **Requires root for configuration**: LKRG settings require root access to change

4. **Performance overhead**: Integrity checks add 2-5% CPU overhead (configurable)

### What LinMon Cannot Do (Without LKRG)

1. **Cannot prevent module loading**: LinMon detects, doesn't prevent

2. **Cannot find hidden modules**: Requires LKRG's memory scanning

3. **Cannot verify kernel integrity**: LinMon monitors events, not kernel structures

**Together**: LinMon (detection) + LKRG (prevention) = Defense-in-Depth

---

## Troubleshooting

### "LKRG not found" when running scripts

**Problem**: LKRG kernel module not installed or loaded

**Solution**:
```bash
# Check if installed
lsmod | grep lkrg

# If not loaded, load it
sudo modprobe lkrg

# If modprobe fails, LKRG not installed
# Install: See "Installation" section above
```

### "LinMon not running" error

**Problem**: Scripts require LinMon to be running first

**Solution**:
```bash
# Start LinMon
sudo systemctl start linmond

# Verify
sudo systemctl status linmond

# Then run LKRG script
sudo ./linmon-enable-lockdown.sh
```

### LKRG breaks after kernel update

**Problem**: LKRG is a kernel module and must be rebuilt for new kernels

**Solution** (if using DKMS):
```bash
# Rebuild LKRG for new kernel
sudo dkms autoinstall

# Load LKRG
sudo modprobe lkrg

# Verify
lsmod | grep lkrg
```

**Solution** (if built from source):
```bash
cd lkrg
make clean
make
sudo make install
sudo modprobe lkrg
```

### Can't load legitimate modules

**Problem**: LKRG `block_modules=1` prevents ALL module loading

**Solution**: Temporarily disable blocking (see Workflow 3 above)

---

## LKRG Configuration

### Tuning LKRG Settings

LKRG provides sysfs interface for runtime configuration:

```bash
# Check all settings
ls /sys/kernel/lkrg/
```

**Key settings**:

| Setting | Default | Description |
|---------|---------|-------------|
| `block_modules` | 0 | Block kernel module loading (0=off, 1=on) |
| `interval` | 15 | Integrity check interval in seconds (0=disable periodic) |
| `log_level` | 3 | Log verbosity (0=none, 4=debug) |
| `profile_enforce` | 2 | Enforcement level (0=log only, 2=block) |

**Example tuning**:
```bash
# More aggressive integrity checking
echo 5 | sudo tee /sys/kernel/lkrg/interval

# More verbose logging
echo 4 | sudo tee /sys/kernel/lkrg/log_level

# Make persistent
cat > /etc/sysctl.d/99-lkrg.conf <<EOF
kernel.lkrg.interval = 5
kernel.lkrg.block_modules = 1
kernel.lkrg.log_level = 4
EOF
```

---

## Alternative: Native Kernel Lockdown

If LKRG is not available, use native kernel lockdown mode (kernel >= 5.4):

```bash
# Enable at boot (add to GRUB)
sudo nano /etc/default/grub

# Add to GRUB_CMDLINE_LINUX:
lockdown=confidentiality

# Update GRUB
sudo update-grub
sudo reboot

# Verify
cat /sys/kernel/security/lockdown
# Expected: [confidentiality]
```

**Difference from LKRG**:
- ✅ No external dependency (built into kernel)
- ❌ Boot-time only (cannot toggle at runtime like LKRG)
- ❌ No hidden module detection
- ❌ No integrity checking

**Recommendation**: Use both for maximum protection!

---

## Documentation

- **Main README**: `../../README.md`
- **Core scripts**: `../../scripts/README.md`
- **Rootkit prevention**: `../../docs/ROOTKIT_PREVENTION.md`
- **LKRG project**: https://lkrg.org/

---

## License

LKRG is licensed under GPL-2.0.

LinMon integration scripts are licensed under GPL-2.0 (same as LinMon core).

---

**Remember**: LKRG is optional. LinMon works completely standalone without it.

These scripts enhance LinMon with runtime kernel protection for high-security environments.
