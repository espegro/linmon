# Rootkit Prevention Guide

This guide documents preventive controls to block kernel rootkits like Singularity from loading on systems running LinMon.

## Core vs Optional Features

**LinMon core has zero runtime dependencies** - it works completely standalone for detection and monitoring.

**This guide covers optional preventive controls**:
- **Core defenses** (no dependencies): Secure Boot, Lockdown, AppArmor/SELinux, AIDE
- **Optional enhancement** (requires LKRG): Runtime kernel integrity checking

All monitoring and detection works without LKRG. LKRG adds runtime prevention and module hiding detection.

## Defense Strategy

LinMon provides **detection** of malicious activity. This guide adds **prevention** layers to stop rootkits from loading in the first place.

```
Defense-in-Depth Layers:
┌─────────────────────────────────────────┐
│ 1. Secure Boot + Module Signing        │  ← CORE: Blocks unsigned modules
├─────────────────────────────────────────┤
│ 2. Kernel Lockdown Mode                 │  ← CORE: Restricts dangerous operations
├─────────────────────────────────────────┤
│ 3. AppArmor/SELinux Policies            │  ← CORE: Controls insmod/modprobe
├─────────────────────────────────────────┤
│ 4. Capability Restrictions              │  ← CORE: Limits CAP_SYS_MODULE
├─────────────────────────────────────────┤
│ 5. File Integrity Monitoring (AIDE)     │  ← CORE: Detects unauthorized .ko files
├─────────────────────────────────────────┤
│ 6. Runtime Protection (LKRG) [OPTIONAL] │  ← OPTIONAL*: Detects module hiding
└─────────────────────────────────────────┘
```

\* **LKRG is optional** - see [extras/lkrg/README.md](../extras/lkrg/README.md) for installation and configuration.

---

## Layer 1: Kernel Module Signing (Mandatory)

### What It Does

Enforces cryptographic signatures on all kernel modules. Unsigned modules cannot load.

### Implementation

**1. Enable Secure Boot (UEFI)**

```bash
# Check Secure Boot status
mokutil --sb-state
# SecureBoot enabled

# If disabled, enable in UEFI/BIOS settings
# Boot → Security → Secure Boot → Enabled
```

**2. Verify Kernel Module Signing Config**

```bash
# Check kernel config
grep CONFIG_MODULE_SIG /boot/config-$(uname -r)
# CONFIG_MODULE_SIG=y                    # Module signing enabled
# CONFIG_MODULE_SIG_FORCE=y              # REQUIRED for blocking unsigned
# CONFIG_MODULE_SIG_ALL=y                # Sign all modules at build
# CONFIG_MODULE_SIG_SHA256=y             # Signature algorithm
```

**3. Enable Signature Enforcement (if not compiled in)**

```bash
# Boot-time enforcement (add to GRUB)
sudo nano /etc/default/grub

# Add to GRUB_CMDLINE_LINUX:
module.sig_enforce=1

# Update GRUB
sudo update-grub
sudo reboot
```

**4. Test Unsigned Module Rejection**

```bash
# Try to load unsigned module (should fail)
sudo insmod singularity.ko

# Expected error:
# insmod: ERROR: could not insert module singularity.ko: Required key not available
# dmesg | tail
# [12345.678] module: x509 key not found
```

**5. Sign LinMon's BPF Programs (if using custom kernel)**

For environments with custom kernels, sign LinMon at build time:

```bash
# Generate signing keys (one-time setup)
sudo openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der -nodes -days 36500 -subj "/CN=LinMon Module Signing Key/"

# Import to Machine Owner Key (MOK)
sudo mokutil --import MOK.der
# Reboot and follow UEFI prompts to enroll key

# Sign LinMon kernel modules (if applicable)
# Note: LinMon uses eBPF (userspace loaded), not LKM, so this is for reference only
```

### Attack Surface Reduction

| Attack | Without Module Signing | With Module Signing |
|--------|----------------------|---------------------|
| `insmod singularity.ko` | ✅ Loads successfully | ❌ **Blocked**: Signature verification failed |
| `modprobe malicious` | ✅ Loads successfully | ❌ **Blocked**: Required key not available |
| Pre-signed malicious module | ✅ Loads successfully | ⚠️ Loads if signed with valid key |

---

## Layer 2: Kernel Lockdown Mode

### What It Does

Restricts dangerous kernel operations even for root:
- Prevents loading unsigned modules (if not compiled with `CONFIG_MODULE_SIG_FORCE`)
- Blocks `/dev/mem` and `/dev/kmem` access
- Restricts kexec, hibernation, BPF type modifications

### Implementation

**1. Enable Lockdown Mode**

```bash
# Check current status
cat /sys/kernel/security/lockdown
# none [integrity] confidentiality

# Enable at boot (add to GRUB)
sudo nano /etc/default/grub

# Add to GRUB_CMDLINE_LINUX:
lockdown=confidentiality

# Update GRUB
sudo update-grub
sudo reboot
```

**Lockdown Levels**:
- `none`: No restrictions
- `integrity`: Prevents kernel modification (allows signed modules, blocks `/dev/mem`)
- `confidentiality`: Maximum restrictions (blocks unsigned modules, kexec, PCMCIA, etc.)

**2. Verify Lockdown Active**

```bash
cat /sys/kernel/security/lockdown
# none integrity [confidentiality]  ← confidentiality active

# Test /dev/mem access (should fail)
sudo dd if=/dev/mem of=/tmp/mem bs=1024 count=1
# dd: failed to open '/dev/mem': Operation not permitted
```

### Impact on Singularity

```bash
# Attacker tries to load rootkit
sudo insmod singularity.ko
# insmod: ERROR: Lockdown: Loading of unsigned modules is restricted

# Attacker tries /dev/mem attack (common rootkit technique)
echo 0 > /dev/mem
# bash: /dev/mem: Operation not permitted
```

---

## Layer 3: AppArmor/SELinux Policies

### What It Does

Mandatory Access Control (MAC) policies restrict which processes can load kernel modules.

### AppArmor Implementation (Ubuntu)

**1. Create insmod Profile**

```bash
sudo nano /etc/apparmor.d/usr.sbin.insmod
```

```apparmor
#include <tunables/global>

/usr/sbin/insmod {
  #include <abstractions/base>

  # Allow reading module files from trusted paths only
  /lib/modules/** r,
  /usr/lib/modules/** r,

  # Deny loading from untrusted paths
  deny /tmp/** r,
  deny /dev/shm/** r,
  deny /home/** r,
  deny /run/** r,

  # Required capabilities
  capability sys_module,

  # Deny network (modules don't need network)
  deny network,

  # System calls
  /usr/sbin/insmod mr,
  /proc/modules r,
  /sys/module/** r,
}
```

**2. Apply Profile**

```bash
# Load profile
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.insmod

# Verify loaded
sudo aa-status | grep insmod
#   /usr/sbin/insmod (enforce)
```

**3. Test Protection**

```bash
# Try to load from /tmp (should fail)
cd /tmp
sudo insmod singularity.ko

# AppArmor denies:
# insmod: ERROR: could not insert module singularity.ko: Permission denied

# Check denial in logs
sudo dmesg | grep DENIED
# [12345.678] audit: type=1400 audit(1234567890.123:456): apparmor="DENIED" operation="open" profile="/usr/sbin/insmod" name="/tmp/singularity.ko" pid=1234 comm="insmod" requested_mask="r" denied_mask="r"
```

### SELinux Implementation (RHEL)

**1. Create Module Loading Policy**

```bash
# Create policy module
sudo nano insmod_restrict.te
```

```selinux
policy_module(insmod_restrict, 1.0.0)

# Only allow insmod from trusted paths
require {
    type insmod_exec_t;
    type modules_object_t;
}

# Deny loading from untrusted types
neverallow insmod_exec_t ~modules_object_t:file { read open };
```

**2. Compile and Load**

```bash
# Compile policy
checkmodule -M -m -o insmod_restrict.mod insmod_restrict.te
semodule_package -o insmod_restrict.pp -m insmod_restrict.mod

# Install policy
sudo semodule -i insmod_restrict.pp

# Verify
sudo semodule -l | grep insmod_restrict
```

---

## Layer 4: Capability Restrictions

### What It Does

Uses `CAP_SYS_MODULE` restrictions to control who can load kernel modules.

### Implementation with systemd

**1. Restrict insmod to Specific Service**

```bash
sudo nano /etc/systemd/system/module-loader.service
```

```ini
[Unit]
Description=Trusted Module Loader Service
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/load-trusted-modules.sh
CapabilityBoundingSet=CAP_SYS_MODULE
AmbientCapabilities=CAP_SYS_MODULE
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/

[Install]
WantedBy=multi-user.target
```

**2. Drop CAP_SYS_MODULE from Normal Users**

```bash
# Install libcap
sudo apt install libcap2-bin

# Remove CAP_SYS_MODULE from user sessions
sudo nano /etc/security/capability.conf
```

```
# Drop SYS_MODULE from all users except root login
cap_sys_module   root
none            *
```

**3. Use pam_cap**

```bash
# Enable in PAM
sudo nano /etc/pam.d/common-auth
```

Add:
```
auth    optional    pam_cap.so
```

### Test

```bash
# Normal user tries insmod
insmod singularity.ko
# insmod: ERROR: could not insert module: Operation not permitted

# Check capabilities
getpcaps $$
# Capabilities for `12345`: = cap_sys_module-ep  ← missing
```

---

## Layer 5: File Integrity Monitoring (AIDE)

### What It Does

Detects unauthorized `.ko` files appearing on the system.

### Implementation

**1. Install AIDE**

```bash
sudo apt install aide aide-common
```

**2. Configure Monitoring Rules**

```bash
sudo nano /etc/aide/aide.conf
```

```conf
# Monitor /lib/modules for unauthorized .ko files
/lib/modules R+b+sha256

# Monitor common rootkit locations
/tmp R+b+sha256
/dev/shm R+b+sha256
/run R+b+sha256
/usr/src R+b+sha256

# Alert on new .ko files anywhere
!/\.ko$ R+b+sha256
```

**3. Initialize Database**

```bash
# Create baseline
sudo aideinit

# Move database to production
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

**4. Schedule Daily Checks**

```bash
# Run daily via cron
sudo nano /etc/cron.daily/aide
```

```bash
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Report $(hostname)" admin@example.com
```

**5. Test Detection**

```bash
# Simulate attacker placing rootkit
sudo cp singularity.ko /tmp/

# Run AIDE check
sudo aide --check

# Output:
# found differences between database and filesystem
# added: /tmp/singularity.ko
```

---

## Layer 6: Runtime Protection (LKRG) [OPTIONAL]

### Important: LKRG is Optional

**LKRG is NOT required for LinMon to work.** Core rootkit prevention (Layers 1-5) provides strong protection without external dependencies.

LKRG adds:
- Runtime kernel integrity checking
- Hidden module detection
- Runtime module blocking

For complete LKRG documentation, see **[extras/lkrg/README.md](../extras/lkrg/README.md)**.

### What It Does

Detects runtime kernel modifications, hidden modules, privilege escalation.

### Quick Setup

**Installation**:
```bash
# Ubuntu (build from source)
git clone https://github.com/lkrg-org/lkrg
cd lkrg && make && sudo make install

# RHEL/Rocky (EPEL)
sudo dnf install lkrg
```

**Basic configuration**:
```bash
# Load LKRG
sudo modprobe lkrg

# Configure
echo 5 > /sys/kernel/lkrg/interval  # Check every 5 seconds
echo 1 > /sys/kernel/lkrg/block_modules  # Block new module loading
```

**For complete setup**, including:
- LinMon + LKRG integration
- BPF load failure alerting
- Lockdown-after-load configuration
- Troubleshooting

See **[extras/lkrg/README.md](../extras/lkrg/README.md)** and **[extras/lkrg/linmon-enable-lockdown.sh](../extras/lkrg/linmon-enable-lockdown.sh)**.

---

## Complete Implementation Script (Core Features)

**Note**: This script implements **core hardening only** (Layers 1-5). LKRG (Layer 6) is optional - see `extras/lkrg/` for LKRG-specific scripts.

Create `/usr/local/sbin/harden-against-rootkits.sh`:

```bash
#!/bin/bash
set -e

echo "=== LinMon Rootkit Hardening Script ==="

# 1. Verify Secure Boot
echo "[1/6] Checking Secure Boot..."
if mokutil --sb-state | grep -q "SecureBoot enabled"; then
    echo "✓ Secure Boot enabled"
else
    echo "⚠ Secure Boot disabled - enable in UEFI/BIOS"
fi

# 2. Enable kernel lockdown
echo "[2/6] Enabling kernel lockdown mode..."
if grep -q "lockdown=confidentiality" /proc/cmdline; then
    echo "✓ Kernel lockdown already enabled"
else
    echo "Adding lockdown=confidentiality to GRUB..."
    sudo sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="lockdown=confidentiality /' /etc/default/grub
    sudo update-grub
    echo "⚠ Reboot required for lockdown to take effect"
fi

# 3. [OPTIONAL] Install and configure LKRG
echo "[3/6] Checking for LKRG (optional)..."
if lsmod | grep -q lkrg; then
    echo "✓ LKRG already installed"
elif apt-cache show lkrg-dkms &>/dev/null; then
    echo "LKRG available - installing (optional)..."
    sudo apt install -y lkrg-dkms
    sudo modprobe lkrg

    cat <<EOF | sudo tee /etc/sysctl.d/99-lkrg.conf
kernel.lkrg.interval = 5
kernel.lkrg.block_modules = 1
kernel.lkrg.log_level = 4
EOF

    sudo sysctl -p /etc/sysctl.d/99-lkrg.conf
    echo "✓ LKRG configured"
else
    echo "⚠ LKRG not available (optional) - see extras/lkrg/README.md"
fi

# 4. Configure AppArmor for insmod
echo "[4/6] Configuring AppArmor..."
cat <<'EOF' | sudo tee /etc/apparmor.d/usr.sbin.insmod
#include <tunables/global>

/usr/sbin/insmod {
  #include <abstractions/base>

  /lib/modules/** r,
  /usr/lib/modules/** r,

  deny /tmp/** r,
  deny /dev/shm/** r,
  deny /home/** r,
  deny /run/** r,

  capability sys_module,
  deny network,

  /usr/sbin/insmod mr,
  /proc/modules r,
  /sys/module/** r,
}
EOF

sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.insmod
echo "✓ AppArmor profile loaded"

# 5. Install AIDE
echo "[5/6] Installing AIDE..."
sudo apt install -y aide aide-common

# Configure AIDE
cat <<'EOF' | sudo tee -a /etc/aide/aide.conf
/lib/modules R+b+sha256
/tmp R+b+sha256
/dev/shm R+b+sha256
/run R+b+sha256
EOF

# Initialize AIDE database
sudo aideinit
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
echo "✓ AIDE initialized"

# 6. Ensure LinMon starts early
echo "[6/6] Configuring LinMon early boot..."
sudo systemctl edit linmond --full --stdin <<'EOF'
[Unit]
Description=LinMon eBPF monitoring
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target sysinit.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/linmond
Restart=on-failure
RestartSec=5

[Install]
WantedBy=sysinit.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable linmond
echo "✓ LinMon configured for early boot"

echo ""
echo "=== Hardening Complete ==="
echo ""
echo "Summary:"
echo "  ✓ Secure Boot verified"
echo "  ✓ Kernel lockdown configured (reboot required)"
if lsmod | grep -q lkrg; then
    echo "  ✓ LKRG installed and configured (optional)"
else
    echo "  ⚠ LKRG not installed (optional) - see extras/lkrg/README.md"
fi
echo "  ✓ AppArmor profile for insmod created"
echo "  ✓ AIDE file integrity monitoring enabled"
echo "  ✓ LinMon early boot configured"
echo ""
echo "NEXT STEPS:"
echo "  1. Reboot system to activate kernel lockdown"
if lsmod | grep -q lkrg; then
    echo "  2. Verify LKRG: lsmod | grep lkrg"
fi
echo "  3. Test insmod restriction: sudo insmod /tmp/test.ko"
echo "  4. Monitor AIDE: sudo aide --check"
echo ""
```

Make executable:

```bash
sudo chmod +x /usr/local/sbin/harden-against-rootkits.sh
sudo /usr/local/sbin/harden-against-rootkits.sh
```

---

## Testing the Defenses

### Simulate Singularity Attack

```bash
# 1. Try to load from /tmp (AppArmor should block)
cd /tmp
sudo insmod singularity.ko
# Expected: insmod: ERROR: could not insert module: Permission denied

# 2. Try to load from /lib/modules without signature (Secure Boot should block)
sudo cp singularity.ko /lib/modules/$(uname -r)/
sudo insmod /lib/modules/$(uname -r)/singularity.ko
# Expected: insmod: ERROR: Required key not available

# 3. Check AIDE detection
sudo aide --check
# Expected: added: /tmp/singularity.ko

# 4. Check LKRG logs
sudo dmesg | grep LKRG
# Expected: LKRG: Module loading blocked

# 5. Verify LinMon logged attempt
sudo tail /var/log/linmon/events.json
# Expected: {"type": "process_exec", "cmdline": "insmod singularity.ko", ...}
```

---

## Attack Surface Comparison

| Attack Vector | Before Hardening | After Core Hardening | With LKRG (Optional) |
|--------------|------------------|----------------------|----------------------|
| `insmod singularity.ko` from /tmp | ✅ Succeeds | ❌ **Blocked by AppArmor** | ❌ **Blocked by AppArmor** |
| Load unsigned module | ✅ Succeeds | ❌ **Blocked by Secure Boot** | ❌ **Blocked by Secure Boot** |
| Load after boot | ✅ Succeeds | ⚠️ Possible if signed | ❌ **Blocked by LKRG** |
| `/dev/mem` attack | ✅ Succeeds | ❌ **Blocked by lockdown mode** | ❌ **Blocked by lockdown mode** |
| ftrace hooking | ✅ Succeeds | ⚠️ Possible, detected by LinMon | ⚠️ Detected by LKRG + LinMon |
| Module hiding | ✅ Undetected | ⚠️ Detected by LinMon (tamper detection) | ⚠️ **Detected by LKRG + LinMon** |
| Privilege escalation | ⚠️ Detected by LinMon | ⚠️ Detected by LinMon | ✅ **Prevented by LKRG + detected by LinMon** |

---

## Monitoring and Alerting

### Daily Security Checks

```bash
# Create daily security report
sudo nano /usr/local/sbin/daily-security-check.sh
```

```bash
#!/bin/bash

REPORT="/var/log/linmon/daily-security-$(date +%Y%m%d).txt"

{
    echo "=== Daily Security Report $(date) ==="
    echo ""

    echo "1. Secure Boot Status:"
    mokutil --sb-state
    echo ""

    echo "2. Kernel Lockdown Status:"
    cat /sys/kernel/security/lockdown
    echo ""

    echo "3. LKRG Status (optional):"
    if lsmod | grep -q lkrg; then
        echo "LKRG loaded"
        cat /sys/kernel/lkrg/block_modules
    else
        echo "LKRG not installed (optional)"
    fi
    echo ""

    echo "4. AppArmor Status:"
    sudo aa-status | grep insmod
    echo ""

    echo "5. AIDE File Integrity:"
    sudo aide --check || echo "File changes detected!"
    echo ""

    echo "6. LinMon Events (last 24h):"
    sudo journalctl -u linmond --since "24 hours ago" --no-pager
    echo ""

    echo "7. Suspicious insmod attempts:"
    sudo grep "insmod.*ERROR" /var/log/syslog | tail -20
    echo ""

} > "$REPORT"

# Email report
mail -s "Security Report $(hostname) $(date +%Y-%m-%d)" admin@example.com < "$REPORT"
```

```bash
sudo chmod +x /usr/local/sbin/daily-security-check.sh

# Add to cron
echo "0 6 * * * /usr/local/sbin/daily-security-check.sh" | sudo crontab -
```

---

## Maintenance

### Allow Legitimate Module Loading

**Core approach** (no LKRG):
```bash
# Load module from trusted path
sudo modprobe my_trusted_module

# Update AIDE baseline
sudo aide --update
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

**If using LKRG** (optional - see [extras/lkrg/README.md](../extras/lkrg/README.md)):
```bash
# 1. Temporarily disable LKRG blocking
echo 0 | sudo tee /sys/kernel/lkrg/block_modules

# 2. Load module from trusted path
sudo modprobe my_trusted_module

# 3. Re-enable LKRG blocking
echo 1 | sudo tee /sys/kernel/lkrg/block_modules

# 4. Update AIDE baseline
sudo aide --update
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

### Kernel Updates

**Core approach**:
```bash
# Update AIDE baseline after kernel update
sudo aide --update
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Restart LinMon
sudo systemctl restart linmond
```

**If using LKRG** (optional):
```bash
# Rebuild LKRG for new kernel
sudo dkms autoinstall

# Verify LKRG loads on boot
sudo systemctl reboot
lsmod | grep lkrg

# See extras/lkrg/README.md for troubleshooting
```

---

## Limitations

### What This Does NOT Prevent

1. **Exploits loaded before hardening**: If rootkit loads during boot before protections activate
2. **Firmware-level rootkits**: UEFI/BIOS malware (requires Secure Boot + UEFI firmware updates)
3. **Legitimate signed modules**: If attacker has access to signing keys
4. **User-space rootkits**: LD_PRELOAD, ptrace-based (LinMon still detects these)

### Residual Risks

- **Social engineering**: Attacker tricks admin to disable protections
- **Physical access**: Attacker boots from USB, disables Secure Boot
- **Supply chain**: Pre-compromised hardware/firmware

---

## Conclusion

### Core Protection (No External Dependencies)

With **core hardening** (Layers 1-5):

```
Singularity Attack Flow:
1. Attacker: sudo insmod singularity.ko
   → AppArmor: DENIED (untrusted path)

2. Attacker: sudo cp singularity.ko /lib/modules/ && sudo insmod /lib/modules/singularity.ko
   → Secure Boot: DENIED (signature verification failed)

3. Attacker: Disable Secure Boot in BIOS
   → Physical access required - out of scope for software controls

4. Attacker: Signs module with stolen key
   → LinMon: Logs all activity (tamper detection)
   → AIDE: Detects new file
   → Detection via log analysis
```

**Result**: Core hardening provides **strong protection** against Singularity using only standard Linux security features.

**Recommended baseline**: Secure Boot + Lockdown + AppArmor + AIDE + LinMon

---

### Enhanced Protection (With LKRG)

Adding **LKRG** (optional) enhances protection:

```
Singularity Attack Flow (with LKRG):
1-3. Same as core protection (AppArmor, Secure Boot blocks)

4. Attacker: Signs module with stolen key
   → LKRG: Blocks module loading after boot (block_modules=1)
   → LKRG: Detects module hiding, privilege escalation
   → LinMon: Logs all activity
   → AIDE: Detects new file
   → Multi-layer detection + runtime prevention
```

**Result**: LKRG adds runtime prevention and active integrity checking.

**Enhanced baseline**: Core hardening + LKRG

See **[extras/lkrg/README.md](../extras/lkrg/README.md)** for LKRG setup.
