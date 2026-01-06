#!/bin/bash
# Master test runner for LinMon v1.4.0 security features
# Runs all three feature tests in sequence

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}LinMon v1.4.0 Feature Test Suite${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

# Check if LinMon is running
if ! systemctl is-active --quiet linmond 2>/dev/null; then
    echo -e "${RED}ERROR: LinMon is not running${NC}"
    echo "Start LinMon with: sudo systemctl start linmond"
    exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Track test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

run_test() {
    local test_script="$1"
    local test_name="$2"

    echo -e "${BLUE}========================================"
    echo "Running: $test_name"
    echo -e "========================================${NC}"
    echo ""

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ -f "$test_script" ]; then
        if "$test_script"; then
            PASSED_TESTS=$((PASSED_TESTS + 1))
            echo -e "${GREEN}✓ $test_name completed${NC}"
        else
            FAILED_TESTS=$((FAILED_TESTS + 1))
            echo -e "${RED}✗ $test_name failed${NC}"
        fi
    else
        echo -e "${RED}ERROR: Test script not found: $test_script${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi

    echo ""
    sleep 1
}

# Check if running as root (needed for some tests)
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}WARNING: Not running as root${NC}"
    echo "Some tests (SUID, cron, systemd) require root privileges"
    echo "Run with: sudo $0"
    echo ""
    read -p "Continue with user-level tests only? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    echo ""
fi

# Run all tests
run_test "$SCRIPT_DIR/test_ssh_keys.sh" "SSH Key Detection (T1552.004, T1098.004)"
run_test "$SCRIPT_DIR/test_suid.sh" "SUID/SGID Manipulation (T1548.001)"
run_test "$SCRIPT_DIR/test_persistence.sh" "Persistence Mechanisms (T1053, T1547)"

# Print summary
echo -e "${BLUE}========================================="
echo "Test Summary"
echo -e "=========================================${NC}"
echo ""
echo "Total tests run: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
if [ $FAILED_TESTS -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"
else
    echo "Failed: 0"
fi
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    echo ""
    echo "LinMon v1.4.0 features are working correctly."
    echo ""
    echo "To enable all new features in production:"
    echo "  1. Edit /etc/linmon/linmon.conf"
    echo "  2. Set: monitor_persistence = true"
    echo "  3. Set: monitor_suid = true"
    echo "  4. monitor_cred_read = true (already enabled by default)"
    echo "  5. Reload: sudo systemctl reload linmond"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    echo ""
    echo "Troubleshooting steps:"
    echo "  1. Check LinMon is running: sudo systemctl status linmond"
    echo "  2. Check config flags in /etc/linmon/linmon.conf:"
    echo "       monitor_cred_read = true"
    echo "       monitor_persistence = true"
    echo "       monitor_suid = true"
    echo "  3. Reload config: sudo systemctl reload linmond"
    echo "  4. Check logs: sudo journalctl -u linmond -n 50"
    echo "  5. Review events: sudo tail -50 /var/log/linmon/events.json | jq"
    exit 1
fi
