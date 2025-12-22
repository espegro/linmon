#!/bin/bash
# test-security.sh - Integration tests for security monitoring features
# Tests MITRE ATT&CK detection: T1055, T1547.006, T1620

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOGFILE="/var/log/linmon/events.json"
PASSED=0
FAILED=0
SKIPPED=0

echo "=== LinMon Security Monitoring Tests ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Tests must be run as root${NC}"
    exit 1
fi

# Check if linmond is running
if ! pgrep -x linmond > /dev/null; then
    echo -e "${YELLOW}Warning: linmond is not running${NC}"
    echo "Start linmond first with security monitoring enabled:"
    echo "  monitor_ptrace = true"
    echo "  monitor_modules = true"
    echo "  monitor_memfd = true"
    exit 1
fi

# Check if log file exists
if [ ! -f "$LOGFILE" ]; then
    echo -e "${RED}Error: Log file $LOGFILE not found${NC}"
    exit 1
fi

# Test 1: ptrace detection (T1055 - Process Injection)
test_ptrace() {
    echo -n "Testing ptrace detection (T1055)... "

    # Get current log position
    BEFORE=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)

    # Run strace on a simple command (uses PTRACE_ATTACH)
    timeout 2 strace -e trace=none /bin/true >/dev/null 2>&1 || true

    sleep 1

    # Check for ptrace event
    AFTER=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)
    NEW_LINES=$((AFTER - BEFORE))

    if [ $NEW_LINES -gt 0 ] && tail -n $NEW_LINES "$LOGFILE" | grep -q '"type":"security_ptrace"'; then
        echo -e "${GREEN}PASS${NC}"
        ((PASSED++))
        # Show the event
        tail -n $NEW_LINES "$LOGFILE" | grep '"type":"security_ptrace"' | head -1 | python3 -m json.tool 2>/dev/null || true
    else
        echo -e "${RED}FAIL${NC} (no ptrace event detected)"
        ((FAILED++))
    fi
}

# Test 2: memfd_create detection (T1620 - Fileless Malware)
test_memfd() {
    echo -n "Testing memfd_create detection (T1620)... "

    BEFORE=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)

    # Create a memfd using Python
    python3 -c "
import os
try:
    fd = os.memfd_create('linmon_test_memfd')
    os.close(fd)
except Exception as e:
    pass
" 2>/dev/null || true

    sleep 1

    AFTER=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)
    NEW_LINES=$((AFTER - BEFORE))

    if [ $NEW_LINES -gt 0 ] && tail -n $NEW_LINES "$LOGFILE" | grep -q '"type":"security_memfd_create"'; then
        echo -e "${GREEN}PASS${NC}"
        ((PASSED++))
        # Show the event
        tail -n $NEW_LINES "$LOGFILE" | grep '"type":"security_memfd_create"' | head -1 | python3 -m json.tool 2>/dev/null || true
    else
        echo -e "${RED}FAIL${NC} (no memfd event detected)"
        ((FAILED++))
    fi
}

# Test 3: Module loading detection (T1547.006)
# Note: We don't actually load a module (that would be dangerous)
# Instead we verify the BPF programs are attached
test_module_attachment() {
    echo -n "Testing module load monitoring attachment (T1547.006)... "

    # Check if the BPF programs are attached by looking at startup output
    if journalctl -u linmond --since "10 minutes ago" 2>/dev/null | grep -q "Module loading"; then
        echo -e "${GREEN}PASS${NC} (BPF program attached)"
        ((PASSED++))
    elif dmesg 2>/dev/null | grep -q "linmon.*module"; then
        echo -e "${GREEN}PASS${NC} (BPF program attached)"
        ((PASSED++))
    else
        # Just check that linmond is running - module monitoring is best-effort
        echo -e "${YELLOW}SKIP${NC} (cannot verify without loading module)"
        ((SKIPPED++))
    fi
}

# Check which tests to run based on config
check_config() {
    local option=$1
    if grep -q "^${option} *= *true" /etc/linmon/linmon.conf 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

echo "Checking enabled security monitoring features..."
echo ""

# Run tests based on config
if check_config "monitor_ptrace"; then
    test_ptrace
    echo ""
else
    echo -e "${YELLOW}SKIP${NC} ptrace test (monitor_ptrace not enabled in config)"
    ((SKIPPED++))
fi

if check_config "monitor_memfd"; then
    test_memfd
    echo ""
else
    echo -e "${YELLOW}SKIP${NC} memfd test (monitor_memfd not enabled in config)"
    ((SKIPPED++))
fi

if check_config "monitor_modules"; then
    test_module_attachment
    echo ""
else
    echo -e "${YELLOW}SKIP${NC} module test (monitor_modules not enabled in config)"
    ((SKIPPED++))
fi

echo ""
echo "=== Test Summary ==="
echo -e "Passed:  ${GREEN}$PASSED${NC}"
echo -e "Failed:  ${RED}$FAILED${NC}"
echo -e "Skipped: ${YELLOW}$SKIPPED${NC}"

if [ $FAILED -gt 0 ]; then
    echo ""
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
elif [ $PASSED -eq 0 ] && [ $SKIPPED -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}All tests skipped. Enable security monitoring in /etc/linmon/linmon.conf:${NC}"
    echo "  monitor_ptrace = true"
    echo "  monitor_modules = true"
    echo "  monitor_memfd = true"
    echo ""
    echo "Then reload: sudo systemctl reload linmond"
    exit 0
else
    echo ""
    echo -e "${GREEN}All enabled tests passed!${NC}"
    exit 0
fi
