#!/bin/bash
# Test script for LinMon SUID/SGID manipulation detection (T1548.001)
# Tests EVENT_SECURITY_SUID

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "LinMon SUID/SGID Detection Test"
echo "========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This test must be run as root${NC}"
    echo "Run with: sudo $0"
    exit 1
fi

# Check if LinMon is running
if ! systemctl is-active --quiet linmond; then
    echo -e "${RED}ERROR: LinMon is not running${NC}"
    echo "Start LinMon with: sudo systemctl start linmond"
    exit 1
fi

# Check if monitor_suid is enabled
if ! grep -q "^monitor_suid = true" /etc/linmon/linmon.conf 2>/dev/null; then
    echo -e "${YELLOW}WARNING: monitor_suid is not enabled in /etc/linmon/linmon.conf${NC}"
    echo "Enable with: monitor_suid = true"
    echo "Then reload: sudo systemctl reload linmond"
    echo ""
    echo "Continuing anyway (test may not detect events)..."
    echo ""
fi

# Get current line count of log file
LOG_FILE="/var/log/linmon/events.json"
if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}ERROR: Log file $LOG_FILE not found${NC}"
    exit 1
fi

INITIAL_LINES=$(wc -l < "$LOG_FILE")

echo "Test 1: SUID Bit Setting Detection"
echo "------------------------------------"

# Create a test binary
TEST_BINARY="/tmp/linmon_test_suid"
echo "Creating test binary: $TEST_BINARY"
cp /bin/ls "$TEST_BINARY"
chmod 755 "$TEST_BINARY"

echo "Setting SUID bit with: chmod u+s $TEST_BINARY"
chmod u+s "$TEST_BINARY"

# Wait for event to be logged
sleep 2

# Check if event was logged
echo "Checking for security_suid event with suid=true..."
NEW_EVENTS=$(tail -n +$((INITIAL_LINES + 1)) "$LOG_FILE" | grep '"type":"security_suid"' | grep '"suid":true' | head -1)

if [ -n "$NEW_EVENTS" ]; then
    echo -e "${GREEN}✓ SUID bit setting detected!${NC}"
    echo "Event: $(echo "$NEW_EVENTS" | jq -c '{type, path, mode, suid, sgid, comm, username}')"
else
    echo -e "${RED}✗ SUID bit setting NOT detected${NC}"
    echo "Check that monitor_suid=true in /etc/linmon/linmon.conf"
fi

echo ""
echo "Test 2: SGID Bit Setting Detection"
echo "------------------------------------"

# Update initial line count
INITIAL_LINES=$(wc -l < "$LOG_FILE")

# Create another test binary
TEST_BINARY2="/tmp/linmon_test_sgid"
echo "Creating test binary: $TEST_BINARY2"
cp /bin/ls "$TEST_BINARY2"
chmod 755 "$TEST_BINARY2"

echo "Setting SGID bit with: chmod g+s $TEST_BINARY2"
chmod g+s "$TEST_BINARY2"

# Wait for event to be logged
sleep 2

# Check if event was logged
echo "Checking for security_suid event with sgid=true..."
NEW_EVENTS=$(tail -n +$((INITIAL_LINES + 1)) "$LOG_FILE" | grep '"type":"security_suid"' | grep '"sgid":true' | head -1)

if [ -n "$NEW_EVENTS" ]; then
    echo -e "${GREEN}✓ SGID bit setting detected!${NC}"
    echo "Event: $(echo "$NEW_EVENTS" | jq -c '{type, path, mode, suid, sgid, comm, username}')"
else
    echo -e "${RED}✗ SGID bit setting NOT detected${NC}"
    echo "Check that monitor_suid=true in /etc/linmon/linmon.conf"
fi

echo ""
echo "Test 3: Both SUID and SGID Bits Detection"
echo "-------------------------------------------"

# Update initial line count
INITIAL_LINES=$(wc -l < "$LOG_FILE")

# Create another test binary
TEST_BINARY3="/tmp/linmon_test_both"
echo "Creating test binary: $TEST_BINARY3"
cp /bin/ls "$TEST_BINARY3"
chmod 755 "$TEST_BINARY3"

echo "Setting both SUID and SGID bits with: chmod ug+s $TEST_BINARY3"
chmod ug+s "$TEST_BINARY3"

# Wait for event to be logged
sleep 2

# Check if event was logged
echo "Checking for security_suid event with both suid=true and sgid=true..."
NEW_EVENTS=$(tail -n +$((INITIAL_LINES + 1)) "$LOG_FILE" | grep '"type":"security_suid"' | grep '"suid":true' | grep '"sgid":true' | head -1)

if [ -n "$NEW_EVENTS" ]; then
    echo -e "${GREEN}✓ Both SUID and SGID bits detected!${NC}"
    echo "Event: $(echo "$NEW_EVENTS" | jq -c '{type, path, mode, suid, sgid, comm, username}')"
else
    echo -e "${RED}✗ Both SUID and SGID bits NOT detected${NC}"
    echo "Check that monitor_suid=true in /etc/linmon/linmon.conf"
fi

echo ""
echo "Cleanup"
echo "-------"

# Remove test binaries
echo "Removing test binaries..."
rm -f "$TEST_BINARY" "$TEST_BINARY2" "$TEST_BINARY3"

echo ""
echo "========================================="
echo "Test complete!"
echo "========================================="
echo ""
echo "Review full events with:"
echo "  sudo tail -20 /var/log/linmon/events.json | jq 'select(.type == \"security_suid\")'"
echo ""
echo "Enable monitoring in /etc/linmon/linmon.conf:"
echo "  monitor_suid = true  # T1548.001 SUID/SGID manipulation"
echo "Then reload: sudo systemctl reload linmond"
