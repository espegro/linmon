#!/bin/bash
# Enable lockdown-after-load for LinMon
# This script enables LKRG module blocking AFTER LinMon has loaded its eBPF programs
#
# Usage: sudo ./scripts/linmon-enable-lockdown.sh

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_ok() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root"
    exit 1
fi

echo "╔═══════════════════════════════════════════════════════╗"
echo "║    LinMon Lockdown After Load Configuration           ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# 1. Check if LinMon is running
echo "[1/4] Checking LinMon status..."
if systemctl is-active --quiet linmond; then
    print_ok "LinMon is running"
else
    print_error "LinMon is not running"
    echo "      Start LinMon first: sudo systemctl start linmond"
    exit 1
fi

# Verify BPF programs are actually loaded
if [ -d /sys/fs/bpf/linmon ] || pgrep -x linmond >/dev/null; then
    print_ok "LinMon BPF programs appear to be loaded"
else
    print_warn "Cannot verify BPF programs are loaded"
fi

echo ""

# 2. Check if LKRG is available
echo "[2/4] Checking LKRG availability..."
if lsmod | grep -q lkrg; then
    print_ok "LKRG kernel module is loaded"
else
    print_error "LKRG is not loaded"
    echo ""
    echo "Install LKRG first:"
    echo "  Ubuntu/Debian: sudo apt install lkrg-dkms"
    echo "  RHEL/Rocky:    sudo dnf install lkrg"
    echo ""
    echo "Then load it:"
    echo "  sudo modprobe lkrg"
    exit 1
fi

if [ ! -f /sys/kernel/lkrg/block_modules ]; then
    print_error "LKRG block_modules interface not available"
    echo "      Your LKRG version may not support module blocking"
    exit 1
fi

print_ok "LKRG block_modules interface available"
echo ""

# 3. Enable LKRG module blocking
echo "[3/4] Enabling LKRG module blocking..."

CURRENT_BLOCK_STATUS=$(cat /sys/kernel/lkrg/block_modules)
if [ "$CURRENT_BLOCK_STATUS" = "1" ]; then
    print_warn "LKRG module blocking already enabled"
else
    echo 1 > /sys/kernel/lkrg/block_modules
    BLOCK_STATUS=$(cat /sys/kernel/lkrg/block_modules)

    if [ "$BLOCK_STATUS" = "1" ]; then
        print_ok "LKRG module blocking ENABLED"
        logger -t linmond -p daemon.info "LKRG module blocking enabled - kernel modules locked down after LinMon load"
    else
        print_error "Failed to enable LKRG module blocking"
        exit 1
    fi
fi

echo ""

# 4. Make persistent across reboots
echo "[4/4] Making configuration persistent..."

SYSCTL_CONF="/etc/sysctl.d/99-lkrg.conf"

if [ -f "$SYSCTL_CONF" ]; then
    if grep -q "kernel.lkrg.block_modules.*=.*1" "$SYSCTL_CONF"; then
        print_ok "LKRG blocking already persistent in $SYSCTL_CONF"
    else
        # Add or update the setting
        if grep -q "kernel.lkrg.block_modules" "$SYSCTL_CONF"; then
            sed -i 's/kernel.lkrg.block_modules.*/kernel.lkrg.block_modules = 1/' "$SYSCTL_CONF"
            print_ok "Updated LKRG blocking in $SYSCTL_CONF"
        else
            echo "kernel.lkrg.block_modules = 1" >> "$SYSCTL_CONF"
            print_ok "Added LKRG blocking to $SYSCTL_CONF"
        fi
    fi
else
    # Create new sysctl config
    cat > "$SYSCTL_CONF" <<EOF
# LKRG Configuration for LinMon Lockdown-After-Load
# Enable module blocking after LinMon has loaded its eBPF programs
kernel.lkrg.block_modules = 1
kernel.lkrg.interval = 5
kernel.lkrg.log_level = 4
EOF
    print_ok "Created $SYSCTL_CONF"
fi

# Reload sysctl to verify
sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1
print_ok "Configuration will persist across reboots"

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║              Lockdown Status                          ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "  ✓ LinMon:       Running with eBPF programs loaded"
echo "  ✓ LKRG:         Module blocking ENABLED"
echo "  ✓ Result:       No new kernel modules can load"
echo "  ✓ Persistence:  Enabled via $SYSCTL_CONF"
echo ""
echo "Protection:"
echo "  • Singularity-type rootkits CANNOT load (insmod blocked)"
echo "  • LinMon's eBPF programs remain active"
echo "  • System locked down against kernel module attacks"
echo ""
echo "To allow legitimate module loading temporarily:"
echo "  1. Disable blocking: echo 0 > /sys/kernel/lkrg/block_modules"
echo "  2. Load module:      sudo modprobe your_module"
echo "  3. Re-enable:        echo 1 > /sys/kernel/lkrg/block_modules"
echo ""
echo "To make this permanent part of LinMon startup, add to systemd service:"
echo "  ExecStartPost=/usr/local/sbin/linmon-enable-lockdown.sh"
echo ""
