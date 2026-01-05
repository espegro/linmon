#!/bin/bash
# LinMon System Hardening Script
# Implements multi-layer defense against kernel rootkits like Singularity
#
# Usage: sudo ./scripts/harden-system.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect distribution"
        exit 1
    fi
}

echo "╔═══════════════════════════════════════════════════════╗"
echo "║     LinMon System Hardening Against Rootkits         ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

check_root
detect_distro

print_status "Detected: $DISTRO $VERSION"
echo ""

# ============================================================================
# Layer 1: Secure Boot Verification
# ============================================================================

echo "[1/6] Secure Boot Verification"
echo "────────────────────────────────────────────────────────"

if command -v mokutil &> /dev/null; then
    if mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled"; then
        print_status "Secure Boot is enabled"
    else
        print_warning "Secure Boot is disabled"
        echo "        Enable Secure Boot in your UEFI/BIOS settings"
        echo "        This is CRITICAL for blocking unsigned kernel modules"
    fi
else
    print_warning "mokutil not found (may not be applicable on this system)"
fi

# Check kernel module signing config
if grep -q "CONFIG_MODULE_SIG_FORCE=y" /boot/config-$(uname -r) 2>/dev/null; then
    print_status "Kernel enforces module signature verification"
else
    print_warning "Kernel does NOT enforce module signatures"
    echo "        Consider rebuilding kernel with CONFIG_MODULE_SIG_FORCE=y"
fi

echo ""

# ============================================================================
# Layer 2: Kernel Lockdown Mode
# ============================================================================

echo "[2/6] Kernel Lockdown Mode"
echo "────────────────────────────────────────────────────────"

if [ -f /sys/kernel/security/lockdown ]; then
    LOCKDOWN_STATUS=$(cat /sys/kernel/security/lockdown)

    if echo "$LOCKDOWN_STATUS" | grep -q "\[confidentiality\]"; then
        print_status "Lockdown mode: confidentiality (maximum protection)"
    elif echo "$LOCKDOWN_STATUS" | grep -q "\[integrity\]"; then
        print_status "Lockdown mode: integrity (moderate protection)"
    else
        print_warning "Lockdown mode: none (no protection)"

        # Add lockdown to GRUB if not present
        if ! grep -q "lockdown=" /etc/default/grub; then
            print_status "Adding lockdown=confidentiality to GRUB config"
            sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 lockdown=confidentiality"/' /etc/default/grub

            if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
                update-grub
            else
                grub2-mkconfig -o /boot/grub2/grub.cfg
            fi

            print_warning "Reboot required for lockdown to take effect"
        fi
    fi
else
    print_warning "Kernel lockdown not supported on this kernel"
fi

echo ""

# ============================================================================
# Layer 3: LKRG (Linux Kernel Runtime Guard)
# ============================================================================

echo "[3/6] LKRG (Linux Kernel Runtime Guard)"
echo "────────────────────────────────────────────────────────"

if lsmod | grep -q lkrg; then
    print_status "LKRG is loaded"
else
    print_warning "LKRG not loaded, attempting to install..."

    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        apt-get update
        apt-get install -y lkrg-dkms || print_warning "LKRG installation failed (may not be available in repos)"
    elif [ "$DISTRO" = "rhel" ] || [ "$DISTRO" = "rocky" ] || [ "$DISTRO" = "almalinux" ]; then
        dnf install -y lkrg || print_warning "LKRG installation failed (may not be available in repos)"
    fi

    # Try to load LKRG
    if modprobe lkrg 2>/dev/null; then
        print_status "LKRG loaded successfully"
    else
        print_warning "Could not load LKRG (may require manual installation from source)"
    fi
fi

# Configure LKRG if loaded
if lsmod | grep -q lkrg; then
    cat <<'EOF' > /etc/sysctl.d/99-lkrg.conf
# LKRG Configuration for Rootkit Protection
kernel.lkrg.interval = 5
kernel.lkrg.block_modules = 1
kernel.lkrg.log_level = 4
EOF

    sysctl -p /etc/sysctl.d/99-lkrg.conf >/dev/null 2>&1
    print_status "LKRG configured: 5s check interval, module blocking enabled"
fi

echo ""

# ============================================================================
# Layer 4: AppArmor/SELinux Hardening
# ============================================================================

echo "[4/6] MAC (Mandatory Access Control) Hardening"
echo "────────────────────────────────────────────────────────"

if command -v aa-status &> /dev/null && systemctl is-active --quiet apparmor; then
    print_status "AppArmor is active"

    # Create insmod restriction profile
    cat <<'EOF' > /etc/apparmor.d/usr.sbin.insmod
#include <tunables/global>

/usr/sbin/insmod {
  #include <abstractions/base>

  # Allow reading modules from trusted paths only
  /lib/modules/** r,
  /usr/lib/modules/** r,

  # Deny loading from untrusted paths (common rootkit locations)
  deny /tmp/** r,
  deny /dev/shm/** r,
  deny /home/** r,
  deny /run/** r,
  deny /var/tmp/** r,

  # Required capabilities
  capability sys_module,

  # Deny network access
  deny network,

  # System files
  /usr/sbin/insmod mr,
  /proc/modules r,
  /sys/module/** r,
  /proc/sys/kernel/osrelease r,
}
EOF

    # Also restrict modprobe
    cat <<'EOF' > /etc/apparmor.d/usr.sbin.modprobe
#include <tunables/global>

/usr/sbin/modprobe {
  #include <abstractions/base>
  #include <abstractions/consoles>

  # Allow modules from trusted paths only
  /lib/modules/** r,
  /usr/lib/modules/** r,

  # Deny untrusted paths
  deny /tmp/** r,
  deny /dev/shm/** r,
  deny /home/** r,
  deny /run/** r,

  capability sys_module,
  deny network,

  /usr/sbin/modprobe mr,
  /usr/sbin/insmod Cx -> insmod,
  /proc/** r,
  /sys/** r,
  /etc/modprobe.d/** r,
  /etc/modprobe.conf r,

  profile insmod {
    #include <abstractions/base>
    /usr/sbin/insmod mr,
    /lib/modules/** r,
    /usr/lib/modules/** r,
    capability sys_module,
  }
}
EOF

    apparmor_parser -r /etc/apparmor.d/usr.sbin.insmod 2>/dev/null || print_warning "Failed to load insmod profile"
    apparmor_parser -r /etc/apparmor.d/usr.sbin.modprobe 2>/dev/null || print_warning "Failed to load modprobe profile"

    print_status "AppArmor profiles created for insmod/modprobe"

elif command -v getenforce &> /dev/null; then
    SELINUX_STATUS=$(getenforce)

    if [ "$SELINUX_STATUS" = "Enforcing" ]; then
        print_status "SELinux is enforcing"
    else
        print_warning "SELinux is $SELINUX_STATUS (should be Enforcing)"
    fi
else
    print_warning "Neither AppArmor nor SELinux detected"
fi

echo ""

# ============================================================================
# Layer 5: AIDE (File Integrity Monitoring)
# ============================================================================

echo "[5/6] AIDE (File Integrity Monitoring)"
echo "────────────────────────────────────────────────────────"

if command -v aide &> /dev/null; then
    print_status "AIDE is installed"
else
    print_warning "AIDE not found, installing..."

    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        apt-get install -y aide aide-common
    elif [ "$DISTRO" = "rhel" ] || [ "$DISTRO" = "rocky" ] || [ "$DISTRO" = "almalinux" ]; then
        dnf install -y aide
    fi
fi

# Add monitoring rules for rootkit-prone locations
if [ -f /etc/aide/aide.conf ]; then
    AIDE_CONF="/etc/aide/aide.conf"
elif [ -f /etc/aide.conf ]; then
    AIDE_CONF="/etc/aide.conf"
else
    print_warning "AIDE config file not found"
    AIDE_CONF=""
fi

if [ -n "$AIDE_CONF" ] && ! grep -q "# LinMon rootkit monitoring" "$AIDE_CONF"; then
    cat <<'EOF' >> "$AIDE_CONF"

# LinMon rootkit monitoring rules
/lib/modules R+b+sha256
/tmp R+b+sha256
/dev/shm R+b+sha256
/run R+b+sha256
/var/tmp R+b+sha256
EOF

    print_status "AIDE configured to monitor rootkit-prone locations"

    # Initialize AIDE database if not exists
    if [ ! -f /var/lib/aide/aide.db ]; then
        print_status "Initializing AIDE database (this may take a few minutes)..."
        aideinit

        if [ -f /var/lib/aide/aide.db.new ]; then
            cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            print_status "AIDE database initialized"
        fi
    fi
fi

# Create daily AIDE check cron job
cat <<'EOF' > /etc/cron.daily/aide-check
#!/bin/bash
/usr/bin/aide --check 2>&1 | grep -v "^AIDE found NO differences" || true
EOF

chmod +x /etc/cron.daily/aide-check
print_status "Daily AIDE checks scheduled"

echo ""

# ============================================================================
# Layer 6: LinMon Early Boot Configuration
# ============================================================================

echo "[6/6] LinMon Early Boot Configuration"
echo "────────────────────────────────────────────────────────"

if [ -f /etc/systemd/system/linmond.service ]; then
    # Ensure LinMon starts early in boot process
    if ! grep -q "DefaultDependencies=no" /etc/systemd/system/linmond.service; then
        print_status "Configuring LinMon for early boot..."

        # Create override
        mkdir -p /etc/systemd/system/linmond.service.d
        cat <<'EOF' > /etc/systemd/system/linmond.service.d/early-boot.conf
[Unit]
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target sysinit.target

[Install]
WantedBy=sysinit.target
EOF

        systemctl daemon-reload
        print_status "LinMon configured to start before rootkits can load"
    else
        print_status "LinMon already configured for early boot"
    fi

    systemctl enable linmond 2>/dev/null || true
else
    print_warning "LinMon not installed (run 'make install' first)"
fi

echo ""

# ============================================================================
# Summary and Recommendations
# ============================================================================

echo "╔═══════════════════════════════════════════════════════╗"
echo "║              Hardening Complete                       ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "Protection Layers Implemented:"
echo ""

# Check each layer
LAYERS_OK=0
LAYERS_TOTAL=6

# Layer 1: Secure Boot
if mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled"; then
    print_status "Secure Boot: Enabled"
    LAYERS_OK=$((LAYERS_OK + 1))
else
    print_warning "Secure Boot: Disabled (enable in UEFI/BIOS)"
fi

# Layer 2: Lockdown
if [ -f /sys/kernel/security/lockdown ]; then
    if cat /sys/kernel/security/lockdown | grep -q "\[confidentiality\]"; then
        print_status "Kernel Lockdown: Confidentiality mode"
        LAYERS_OK=$((LAYERS_OK + 1))
    elif cat /sys/kernel/security/lockdown | grep -q "\[integrity\]"; then
        print_warning "Kernel Lockdown: Integrity mode (consider confidentiality)"
    else
        print_warning "Kernel Lockdown: None (reboot to activate)"
    fi
fi

# Layer 3: LKRG
if lsmod | grep -q lkrg; then
    print_status "LKRG: Loaded and active"
    LAYERS_OK=$((LAYERS_OK + 1))
else
    print_warning "LKRG: Not loaded"
fi

# Layer 4: MAC
if aa-status &>/dev/null && aa-status 2>/dev/null | grep -q "insmod"; then
    print_status "AppArmor: Active with insmod restrictions"
    LAYERS_OK=$((LAYERS_OK + 1))
elif command -v getenforce &>/dev/null && [ "$(getenforce)" = "Enforcing" ]; then
    print_status "SELinux: Enforcing"
    LAYERS_OK=$((LAYERS_OK + 1))
else
    print_warning "MAC: Not fully configured"
fi

# Layer 5: AIDE
if command -v aide &>/dev/null && [ -f /var/lib/aide/aide.db ]; then
    print_status "AIDE: Installed with baseline"
    LAYERS_OK=$((LAYERS_OK + 1))
else
    print_warning "AIDE: Not fully initialized"
fi

# Layer 6: LinMon
if systemctl is-enabled linmond &>/dev/null; then
    print_status "LinMon: Enabled for early boot"
    LAYERS_OK=$((LAYERS_OK + 1))
else
    print_warning "LinMon: Not enabled"
fi

echo ""
echo "Protection Score: $LAYERS_OK/$LAYERS_TOTAL layers active"
echo ""

if [ $LAYERS_OK -ge 5 ]; then
    print_status "System is well-protected against rootkits like Singularity"
elif [ $LAYERS_OK -ge 3 ]; then
    print_warning "System has moderate protection (review warnings above)"
else
    print_error "System has weak protection (multiple layers missing)"
fi

echo ""
echo "Next Steps:"
echo "  1. Reboot to activate all kernel parameters"
echo "  2. Test protections: sudo insmod /tmp/test.ko (should fail)"
echo "  3. Monitor logs: sudo journalctl -u linmond -f"
echo "  4. Check AIDE daily: sudo aide --check"
echo ""
echo "Documentation: docs/ROOTKIT_PREVENTION.md"
echo ""
