#!/bin/bash
# Check LinMon lockdown status (both LKRG and native kernel lockdown)
# Can be used without LKRG dependency
#
# Usage: sudo ./scripts/linmon-check-lockdown.sh

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
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

print_info() {
    echo -e "${BLUE}[ℹ]${NC} $1"
}

if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root"
    exit 1
fi

echo "╔═══════════════════════════════════════════════════════╗"
echo "║         LinMon Lockdown Status Report                 ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

PROTECTION_SCORE=0
MAX_SCORE=5

# ============================================================================
# 1. LinMon Status
# ============================================================================

echo "[1/5] LinMon eBPF Status"
echo "────────────────────────────────────────────────────────"

if systemctl is-active --quiet linmond; then
    print_ok "LinMon daemon is running"
    PROTECTION_SCORE=$((PROTECTION_SCORE + 1))

    # Check if BPF programs are loaded
    if [ -d /sys/fs/bpf ] && pgrep -x linmond >/dev/null; then
        print_ok "eBPF programs appear to be loaded"
    fi
else
    print_error "LinMon daemon is NOT running"
    echo "        LinMon must be running for lockdown to be effective"
fi

echo ""

# ============================================================================
# 2. Native Kernel Lockdown Mode
# ============================================================================

echo "[2/5] Native Kernel Lockdown Mode"
echo "────────────────────────────────────────────────────────"

if [ -f /sys/kernel/security/lockdown ]; then
    LOCKDOWN_STATUS=$(cat /sys/kernel/security/lockdown)

    if echo "$LOCKDOWN_STATUS" | grep -q "\[confidentiality\]"; then
        print_ok "Lockdown mode: CONFIDENTIALITY (maximum protection)"
        PROTECTION_SCORE=$((PROTECTION_SCORE + 1))
        print_info "  → Blocks: /dev/mem, kexec, unsigned modules, BPF type modification"
    elif echo "$LOCKDOWN_STATUS" | grep -q "\[integrity\]"; then
        print_warn "Lockdown mode: INTEGRITY (moderate protection)"
        PROTECTION_SCORE=$((PROTECTION_SCORE + 1))
        print_info "  → Blocks: /dev/mem, kexec, hibernation"
        print_info "  → Consider upgrading to confidentiality mode"
    else
        print_error "Lockdown mode: NONE"
        print_info "  → Enable: Add 'lockdown=confidentiality' to GRUB boot params"
    fi
else
    print_warn "Kernel lockdown not supported on this kernel"
    print_info "  → Requires kernel >= 5.4 with CONFIG_SECURITY_LOCKDOWN_LSM=y"
fi

echo ""

# ============================================================================
# 3. LKRG (Linux Kernel Runtime Guard) - Optional but Recommended
# ============================================================================

echo "[3/5] LKRG Runtime Protection (Optional)"
echo "────────────────────────────────────────────────────────"

if lsmod | grep -q lkrg; then
    print_ok "LKRG kernel module is loaded"

    # Check module blocking
    if [ -f /sys/kernel/lkrg/block_modules ]; then
        BLOCK_STATUS=$(cat /sys/kernel/lkrg/block_modules)

        if [ "$BLOCK_STATUS" = "1" ]; then
            print_ok "LKRG module blocking: ENABLED"
            PROTECTION_SCORE=$((PROTECTION_SCORE + 1))
            print_info "  → No new kernel modules can load (Singularity blocked)"
        else
            print_warn "LKRG module blocking: DISABLED"
            print_info "  → Enable: echo 1 > /sys/kernel/lkrg/block_modules"
        fi

        # Check integrity interval
        if [ -f /sys/kernel/lkrg/interval ]; then
            INTERVAL=$(cat /sys/kernel/lkrg/interval)
            if [ "$INTERVAL" -le 15 ]; then
                print_ok "LKRG integrity checks: Every ${INTERVAL}s (good)"
            else
                print_warn "LKRG integrity checks: Every ${INTERVAL}s (consider ≤15s)"
            fi
        fi
    else
        print_warn "LKRG loaded but block_modules interface unavailable"
    fi
else
    print_info "LKRG is NOT installed (optional but recommended)"
    print_info "  → Install: Ubuntu: sudo apt install lkrg-dkms"
    print_info "  → Install: RHEL:   sudo dnf install lkrg"
    print_info "  → Benefits: Runtime module blocking, hidden module detection"
fi

echo ""

# ============================================================================
# 4. Module Signature Enforcement
# ============================================================================

echo "[4/5] Module Signature Enforcement"
echo "────────────────────────────────────────────────────────"

if command -v mokutil &>/dev/null; then
    if mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled"; then
        print_ok "Secure Boot: ENABLED"
        PROTECTION_SCORE=$((PROTECTION_SCORE + 1))
        print_info "  → Unsigned modules cannot load at boot"
    else
        print_warn "Secure Boot: DISABLED"
        print_info "  → Enable in UEFI/BIOS settings for signature enforcement"
    fi
fi

# Check kernel module signing config
if grep -q "CONFIG_MODULE_SIG_FORCE=y" /boot/config-$(uname -r) 2>/dev/null; then
    print_ok "Kernel enforces module signatures"
else
    print_warn "Kernel does NOT enforce module signatures"
    print_info "  → Consider kernel with CONFIG_MODULE_SIG_FORCE=y"
fi

echo ""

# ============================================================================
# 5. Additional Protections
# ============================================================================

echo "[5/5] Additional Security Controls"
echo "────────────────────────────────────────────────────────"

# AppArmor/SELinux
if command -v aa-status &>/dev/null && systemctl is-active --quiet apparmor; then
    if aa-status 2>/dev/null | grep -q "insmod"; then
        print_ok "AppArmor: Active with insmod restrictions"
        PROTECTION_SCORE=$((PROTECTION_SCORE + 1))
    else
        print_warn "AppArmor: Active but no insmod profile"
        print_info "  → Run: sudo ./scripts/harden-system.sh"
    fi
elif command -v getenforce &>/dev/null; then
    if [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
        print_ok "SELinux: Enforcing"
        PROTECTION_SCORE=$((PROTECTION_SCORE + 1))
    else
        print_warn "SELinux: Not enforcing"
    fi
else
    print_warn "Neither AppArmor nor SELinux active"
fi

# AIDE
if command -v aide &>/dev/null && [ -f /var/lib/aide/aide.db ]; then
    print_ok "AIDE: Installed with baseline"
else
    print_info "AIDE: Not configured (file integrity monitoring)"
fi

echo ""

# ============================================================================
# Summary and Recommendations
# ============================================================================

echo "╔═══════════════════════════════════════════════════════╗"
echo "║              Protection Summary                       ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

PERCENTAGE=$((PROTECTION_SCORE * 100 / MAX_SCORE))

echo "Protection Score: $PROTECTION_SCORE / $MAX_SCORE ($PERCENTAGE%)"
echo ""

if [ $PROTECTION_SCORE -ge 4 ]; then
    print_ok "STRONG protection against rootkits like Singularity"
    echo ""
    echo "Active defenses:"
    [ "$(systemctl is-active linmond 2>/dev/null)" = "active" ] && echo "  ✓ LinMon eBPF monitoring"
    [ -f /sys/kernel/security/lockdown ] && grep -q "\[confidentiality\]" /sys/kernel/security/lockdown 2>/dev/null && echo "  ✓ Kernel lockdown (confidentiality)"
    lsmod | grep -q lkrg && [ "$(cat /sys/kernel/lkrg/block_modules 2>/dev/null)" = "1" ] && echo "  ✓ LKRG module blocking"
    mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled" && echo "  ✓ Secure Boot enabled"

elif [ $PROTECTION_SCORE -ge 2 ]; then
    print_warn "MODERATE protection - some defenses missing"
    echo ""
    echo "Recommendations:"

    [ "$(systemctl is-active linmond 2>/dev/null)" != "active" ] && echo "  → Start LinMon: sudo systemctl start linmond"

    if ! grep -q "\[confidentiality\]" /sys/kernel/security/lockdown 2>/dev/null; then
        echo "  → Enable kernel lockdown: Add 'lockdown=confidentiality' to GRUB"
    fi

    if ! lsmod | grep -q lkrg; then
        echo "  → Install LKRG: sudo apt install lkrg-dkms (optional but recommended)"
    fi

else
    print_error "WEAK protection - vulnerable to rootkits!"
    echo ""
    echo "CRITICAL actions required:"
    echo "  1. Run hardening script: sudo ./scripts/harden-system.sh"
    echo "  2. Enable Secure Boot in UEFI/BIOS"
    echo "  3. Start LinMon: sudo systemctl start linmond"
    echo "  4. Reboot to activate kernel lockdown"
fi

echo ""
echo "Documentation: docs/ROOTKIT_PREVENTION.md"
echo ""

# Return appropriate exit code
if [ $PROTECTION_SCORE -ge 4 ]; then
    exit 0
elif [ $PROTECTION_SCORE -ge 2 ]; then
    exit 1
else
    exit 2
fi
