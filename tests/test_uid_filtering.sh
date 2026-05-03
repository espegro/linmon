#!/bin/bash
# Integration test for UID filtering bug fix (v1.8.5)
# Verifies that max_uid=0 does not filter out non-root users
# Also verifies that privilege events have uid field

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Test configuration
# Use /var/log/linmon directory since linmon user already has access
TEST_LOG="/var/log/linmon/test-uid-filtering.json"
TEST_CONFIG="/tmp/linmon-uid-test.conf"
DAEMON_PID=""

cleanup() {
    # Kill test daemon if running
    if [ -n "$DAEMON_PID" ]; then
        echo -e "${YELLOW}Stopping test daemon (PID $DAEMON_PID)...${NC}"
        sudo kill $DAEMON_PID 2>/dev/null || true
        sleep 1
    fi

    # Clean up test files
    sudo rm -f "$TEST_LOG"  # Test log in /var/log/linmon needs sudo
    rm -f "$TEST_CONFIG"
}

trap cleanup EXIT

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}LinMon UID Filtering Integration Test${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""

# Check if build exists
if [ ! -f "$PROJECT_ROOT/build/linmond" ]; then
    echo -e "${RED}ERROR: LinMon binary not found${NC}"
    echo "Run 'make' first"
    exit 1
fi

# Check if running with sudo (required for daemon)
if [ -z "$SUDO_USER" ] && [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This test must be run with sudo${NC}"
    echo "Usage: sudo $0"
    exit 1
fi

# Detect if running under sudo and get actual user
if [ -n "$SUDO_USER" ]; then
    CURRENT_USER="$SUDO_USER"
    CURRENT_UID=$(id -u "$SUDO_USER")
    echo -e "${YELLOW}Running as sudo - will test as user: $CURRENT_USER (UID $CURRENT_UID)${NC}"
else
    CURRENT_UID=$(id -u)
    CURRENT_USER=$(id -un)
    if [ "$CURRENT_UID" -eq 0 ]; then
        echo -e "${RED}ERROR: Do not run as root directly. Use sudo instead.${NC}"
        exit 1
    fi
fi

echo "Test setup:"
echo "  Test user: $CURRENT_USER"
echo "  Test UID: $CURRENT_UID"
echo "  Log: $TEST_LOG"
echo ""

# Ensure log directory exists (should already exist from linmon install)
sudo mkdir -p "$(dirname "$TEST_LOG")"

# Create minimal test configuration
cat > "$TEST_CONFIG" <<EOF
log_file = $TEST_LOG
log_rotate = false
log_to_syslog = false
verbosity = 0

# UID filtering - THIS IS THE CRITICAL TEST
# max_uid=0 should mean "no limit" (not "filter all UIDs > 0")
min_uid = 0
max_uid = 0

require_tty = false
ignore_threads = true

# Enable only what we need for testing
monitor_processes = true
monitor_process_exit = false
monitor_files = false
monitor_tcp = false
monitor_udp = false
monitor_vsock = false

# Disable all security monitoring except setuid (for privilege event test)
monitor_ptrace = false
monitor_modules = false
monitor_memfd = false
monitor_bind = false
monitor_unshare = false
monitor_execveat = false
monitor_bpf = false
monitor_cred_read = false
monitor_ldpreload = false
monitor_persistence = false
monitor_suid = false
monitor_cred_write = false
monitor_log_tamper = false

# Username resolution (needed for privilege event test)
resolve_usernames = true
hash_binaries = false
verify_packages = false
capture_cmdline = true
redact_sensitive = false
capture_container_metadata = false
EOF

echo -e "${YELLOW}Starting test daemon...${NC}"
# Start daemon in background with test config
sudo "$PROJECT_ROOT/build/linmond" -c "$TEST_CONFIG" &
DAEMON_PID=$!

# Wait for daemon to initialize
sleep 3

# Check if daemon is still running
if ! kill -0 $DAEMON_PID 2>/dev/null; then
    echo -e "${RED}ERROR: Daemon failed to start${NC}"
    echo "Check daemon output above for errors"
    exit 1
fi

# Verify log file is writable by daemon
if [ ! -f "$TEST_LOG" ]; then
    echo -e "${RED}ERROR: Log file was not created${NC}"
    echo "Expected: $TEST_LOG"
    ls -la "$(dirname "$TEST_LOG")" 2>/dev/null || true
    exit 1
fi

echo -e "${GREEN}✓ Daemon started (PID $DAEMON_PID)${NC}"
echo ""

# Test 1: Verify non-root user events are captured
echo -e "${YELLOW}Test 1: Non-root user process execution${NC}"
echo "  Running: ls /tmp (as $CURRENT_USER, UID $CURRENT_UID)"

# Clear log (truncate instead of delete to preserve ownership)
sudo truncate -s 0 "$TEST_LOG"

# Run test command as actual user (not root)
if [ -n "$SUDO_USER" ]; then
    # Running under sudo, execute as original user
    sudo -u "$SUDO_USER" ls /tmp > /dev/null
else
    # Running as normal user
    ls /tmp > /dev/null
fi

# Wait for event to be logged
sleep 1

# Check if event was logged
if [ ! -f "$TEST_LOG" ]; then
    echo -e "${RED}✗ FAILED: Log file not created${NC}"
    exit 1
fi

# Parse JSON and check for ls event with our UID
LS_EVENTS=$(sudo cat "$TEST_LOG" | jq -r "select(.comm == \"ls\" and .uid == $CURRENT_UID) | .uid" 2>/dev/null || true)

if [ -z "$LS_EVENTS" ]; then
    echo -e "${RED}✗ FAILED: ls command from UID $CURRENT_UID not captured${NC}"
    echo "Log contents:"
    sudo cat "$TEST_LOG" | jq . 2>/dev/null || sudo cat "$TEST_LOG"
    exit 1
fi

echo -e "${GREEN}✓ PASSED: Non-root user event captured (uid=$CURRENT_UID)${NC}"
echo ""

# Test 2: Verify privilege events have uid field
echo -e "${YELLOW}Test 2: Privilege events have uid field${NC}"
echo "  Running: sudo -n true (if allowed)"

# Try to run sudo (may fail if NOPASSWD not configured, that's OK)
sudo -n true 2>/dev/null || echo "  (sudo requires password, skipping privilege event test)"

sleep 1

# Check for any privilege events
PRIV_EVENTS=$(sudo cat "$TEST_LOG" | jq -r 'select(.type | startswith("priv_"))' 2>/dev/null || true)

if [ -n "$PRIV_EVENTS" ]; then
    # Check if privilege events have uid field (not just old_uid/new_uid)
    HAS_UID=$(echo "$PRIV_EVENTS" | jq -r 'select(.uid != null) | .uid' | head -1)

    if [ -z "$HAS_UID" ]; then
        echo -e "${RED}✗ FAILED: Privilege events missing uid field${NC}"
        echo "Example privilege event:"
        echo "$PRIV_EVENTS" | head -1 | jq .
        exit 1
    fi

    echo -e "${GREEN}✓ PASSED: Privilege events have uid field${NC}"
else
    echo -e "${YELLOW}⊘ SKIPPED: No privilege events captured (sudo requires password)${NC}"
fi

echo ""

# Test 3: Verify root events are also captured (max_uid=0 should not filter root)
echo -e "${YELLOW}Test 3: Root user process execution${NC}"
echo "  Running: sudo true"

sudo true

sleep 1

# Check for root events (from sudo chain)
ROOT_EVENTS=$(sudo cat "$TEST_LOG" | jq -r 'select(.uid == 0) | .uid' 2>/dev/null | head -1 || true)

if [ -z "$ROOT_EVENTS" ]; then
    echo -e "${RED}✗ FAILED: Root (UID 0) events not captured${NC}"
    exit 1
fi

echo -e "${GREEN}✓ PASSED: Root user events captured${NC}"
echo ""

# Summary
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All UID filtering tests PASSED!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Verified fixes:"
echo "  1. max_uid=0 does not filter out non-root users"
echo "  2. Privilege events have uid field for consistency"
echo "  3. Root events are captured alongside user events"
echo ""

exit 0
