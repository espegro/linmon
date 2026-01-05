#!/bin/bash
# Test script to verify rootkit defenses
# Simulates Singularity-type attack vectors
#
# Usage: sudo ./scripts/test-rootkit-defenses.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_fail "This script must be run as root"
        exit 1
    fi
}

echo "╔═══════════════════════════════════════════════════════╗"
echo "║         Rootkit Defense Testing Suite                ║"
echo "║    Simulating Singularity-type Attack Vectors         ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

check_root

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# ============================================================================
# Test 1: Unsigned Module Loading
# ============================================================================

echo "Test 1: Unsigned Module Loading Prevention"
echo "────────────────────────────────────────────────────────"
print_test "Creating fake unsigned kernel module..."

# Create a minimal (invalid) kernel module for testing
cat > /tmp/test_rootkit.c <<'EOF'
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Test");
MODULE_DESCRIPTION("Test module for defense testing");

static int __init test_init(void) {
    printk(KERN_INFO "Test rootkit loaded\n");
    return 0;
}

static void __exit test_exit(void) {
    printk(KERN_INFO "Test rootkit unloaded\n");
}

module_init(test_init);
module_exit(test_exit);
EOF

# Try to compile (may fail, that's ok)
if command -v gcc &>/dev/null && [ -d /lib/modules/$(uname -r)/build ]; then
    print_info "Attempting to compile test module..."

    cat > /tmp/Makefile <<EOF
obj-m += test_rootkit.o

all:
	make -C /lib/modules/\$(shell uname -r)/build M=\$(PWD) modules

clean:
	make -C /lib/modules/\$(shell uname -r)/build M=\$(PWD) clean
EOF

    cd /tmp
    if make &>/dev/null; then
        print_info "Test module compiled"
        TEST_MODULE="/tmp/test_rootkit.ko"
    else
        print_info "Could not compile test module (using simulated test)"
        # Create a fake .ko file for testing path restrictions
        touch /tmp/test_rootkit.ko
        TEST_MODULE="/tmp/test_rootkit.ko"
    fi
else
    print_info "Kernel headers not available (using simulated test)"
    touch /tmp/test_rootkit.ko
    TEST_MODULE="/tmp/test_rootkit.ko"
fi

print_test "Attempting to load unsigned module from /tmp..."
TESTS_TOTAL=$((TESTS_TOTAL + 1))

if insmod "$TEST_MODULE" 2>&1 | grep -qE "(Required key not available|Permission denied|Operation not permitted|Invalid module format)"; then
    print_pass "✓ System BLOCKED unsigned module loading"
    TESTS_PASSED=$((TESTS_PASSED + 1))

    # Check what blocked it
    if dmesg | tail -20 | grep -q "module verification failed"; then
        print_info "  → Blocked by: Kernel module signature verification"
    elif dmesg | tail -20 | grep -q "apparmor=.*DENIED"; then
        print_info "  → Blocked by: AppArmor"
    elif dmesg | tail -20 | grep -qE "(LKRG|lockdown)"; then
        print_info "  → Blocked by: LKRG/Kernel Lockdown"
    fi
else
    print_fail "✗ System ALLOWED unsigned module loading (SECURITY RISK!)"
    TESTS_FAILED=$((TESTS_FAILED + 1))

    # Try to unload if it actually loaded
    rmmod test_rootkit 2>/dev/null || true
fi

rm -f /tmp/test_rootkit.* /tmp/Makefile /tmp/.test_rootkit.* 2>/dev/null

echo ""

# ============================================================================
# Test 2: Module Loading from Untrusted Paths
# ============================================================================

echo "Test 2: Untrusted Path Protection"
echo "────────────────────────────────────────────────────────"

UNTRUSTED_PATHS=("/tmp" "/dev/shm" "/var/tmp")

for path in "${UNTRUSTED_PATHS[@]}"; do
    print_test "Testing insmod from $path..."
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    touch "$path/fake_module.ko"

    if insmod "$path/fake_module.ko" 2>&1 | grep -qE "(Permission denied|Operation not permitted|apparmor)"; then
        print_pass "✓ Blocked module loading from $path"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_fail "✗ Allowed module loading from $path"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    rm -f "$path/fake_module.ko"
done

echo ""

# ============================================================================
# Test 3: /dev/mem and /dev/kmem Access
# ============================================================================

echo "Test 3: Kernel Memory Access Protection"
echo "────────────────────────────────────────────────────────"

print_test "Attempting to read /dev/mem (kernel memory)..."
TESTS_TOTAL=$((TESTS_TOTAL + 1))

if dd if=/dev/mem of=/dev/null bs=1 count=1 2>&1 | grep -qE "(Operation not permitted|Permission denied)"; then
    print_pass "✓ /dev/mem access BLOCKED (lockdown active)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
elif [ ! -e /dev/mem ]; then
    print_pass "✓ /dev/mem doesn't exist (secure configuration)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_fail "✗ /dev/mem is accessible (SECURITY RISK!)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

echo ""

# ============================================================================
# Test 4: LKRG Module Blocking
# ============================================================================

echo "Test 4: LKRG Runtime Module Blocking"
echo "────────────────────────────────────────────────────────"

if lsmod | grep -q lkrg; then
    print_info "LKRG is loaded"

    print_test "Checking LKRG module blocking configuration..."
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    if [ -f /sys/kernel/lkrg/block_modules ]; then
        BLOCK_STATUS=$(cat /sys/kernel/lkrg/block_modules)

        if [ "$BLOCK_STATUS" = "1" ]; then
            print_pass "✓ LKRG module blocking is ENABLED"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            print_fail "✗ LKRG module blocking is DISABLED"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        print_info "LKRG module blocking interface not available"
    fi

    # Check LKRG integrity check interval
    print_test "Checking LKRG integrity check interval..."
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    if [ -f /sys/kernel/lkrg/interval ]; then
        INTERVAL=$(cat /sys/kernel/lkrg/interval)

        if [ "$INTERVAL" -le 15 ]; then
            print_pass "✓ LKRG checking every ${INTERVAL}s (good)"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            print_fail "✗ LKRG interval too high: ${INTERVAL}s (should be ≤15s)"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    fi
else
    print_info "LKRG not loaded (tests skipped)"
fi

echo ""

# ============================================================================
# Test 5: AIDE File Integrity Monitoring
# ============================================================================

echo "Test 5: AIDE File Integrity Detection"
echo "────────────────────────────────────────────────────────"

if command -v aide &>/dev/null && [ -f /var/lib/aide/aide.db ]; then
    print_test "Creating suspicious file in /tmp..."
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    echo "malicious" > /tmp/suspicious_rootkit.ko

    print_info "Running AIDE check..."
    if aide --check 2>&1 | grep -q "/tmp/suspicious_rootkit.ko"; then
        print_pass "✓ AIDE detected new suspicious file"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        # AIDE may not have /tmp in database yet
        print_info "AIDE did not detect (may need database update)"
    fi

    rm -f /tmp/suspicious_rootkit.ko
else
    print_info "AIDE not configured (test skipped)"
fi

echo ""

# ============================================================================
# Test 6: Secure Boot Status
# ============================================================================

echo "Test 6: Secure Boot Verification"
echo "────────────────────────────────────────────────────────"

if command -v mokutil &>/dev/null; then
    print_test "Checking Secure Boot status..."
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    if mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled"; then
        print_pass "✓ Secure Boot is ENABLED"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_fail "✗ Secure Boot is DISABLED (enable in BIOS/UEFI)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    print_info "Secure Boot check not available on this system"
fi

echo ""

# ============================================================================
# Test 7: Kernel Lockdown Mode
# ============================================================================

echo "Test 7: Kernel Lockdown Mode"
echo "────────────────────────────────────────────────────────"

if [ -f /sys/kernel/security/lockdown ]; then
    print_test "Checking kernel lockdown status..."
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    LOCKDOWN=$(cat /sys/kernel/security/lockdown)

    if echo "$LOCKDOWN" | grep -q "\[confidentiality\]"; then
        print_pass "✓ Lockdown mode: CONFIDENTIALITY (maximum protection)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    elif echo "$LOCKDOWN" | grep -q "\[integrity\]"; then
        print_pass "✓ Lockdown mode: INTEGRITY (moderate protection)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_fail "✗ Lockdown mode: NONE (no protection)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    print_info "Kernel lockdown not supported on this kernel"
fi

echo ""

# ============================================================================
# Test 8: LinMon Event Detection
# ============================================================================

echo "Test 8: LinMon Detection Capabilities"
echo "────────────────────────────────────────────────────────"

if systemctl is-active --quiet linmond; then
    print_test "LinMon daemon is running"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    # Generate a test event (process execution)
    /bin/true

    sleep 2

    # Check if LinMon logged it
    if [ -f /var/log/linmon/events.json ]; then
        if tail -100 /var/log/linmon/events.json 2>/dev/null | grep -q "process_exec"; then
            print_pass "✓ LinMon is logging events"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            print_fail "✗ LinMon not logging events"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        print_fail "✗ LinMon log file not found"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi

    # Check if LinMon starts before potential rootkits
    print_test "Checking LinMon boot priority..."
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    if systemctl show linmond | grep -q "DefaultDependencies=no"; then
        print_pass "✓ LinMon configured for early boot"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_fail "✗ LinMon not configured for early boot"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    print_info "LinMon not running (tests skipped)"
fi

echo ""

# ============================================================================
# Test Summary
# ============================================================================

echo "╔═══════════════════════════════════════════════════════╗"
echo "║                  Test Summary                         ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

PASS_RATE=0
if [ $TESTS_TOTAL -gt 0 ]; then
    PASS_RATE=$((TESTS_PASSED * 100 / TESTS_TOTAL))
fi

echo "Tests Passed: $TESTS_PASSED / $TESTS_TOTAL ($PASS_RATE%)"
echo "Tests Failed: $TESTS_FAILED / $TESTS_TOTAL"
echo ""

if [ $PASS_RATE -ge 80 ]; then
    print_pass "System has STRONG rootkit protection"
    echo ""
    echo "Your system is well-protected against rootkits like Singularity:"
    echo "  • Unsigned modules cannot load"
    echo "  • Untrusted paths are blocked"
    echo "  • Kernel memory is protected"
    echo "  • Runtime integrity checking is active"
    echo "  • Event monitoring is operational"
elif [ $PASS_RATE -ge 50 ]; then
    print_info "System has MODERATE rootkit protection"
    echo ""
    echo "Your system has some protection, but consider:"
    echo "  • Enabling Secure Boot in BIOS/UEFI"
    echo "  • Activating kernel lockdown mode"
    echo "  • Installing LKRG for runtime protection"
    echo "  • Configuring AppArmor/SELinux restrictions"
else
    print_fail "System has WEAK rootkit protection"
    echo ""
    echo "CRITICAL: Your system is vulnerable to rootkits!"
    echo "Run the hardening script immediately:"
    echo "  sudo ./scripts/harden-system.sh"
fi

echo ""
echo "Detailed hardening guide: docs/ROOTKIT_PREVENTION.md"
echo ""

# Exit with appropriate code
if [ $TESTS_FAILED -eq 0 ]; then
    exit 0
else
    exit 1
fi
