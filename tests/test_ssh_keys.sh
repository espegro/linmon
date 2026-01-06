#!/bin/bash
# Test script for LinMon SSH key detection (T1552.004, T1098.004)
# Tests EVENT_SECURITY_CRED_READ with ssh_private_key, ssh_authorized_keys, ssh_user_config

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "LinMon SSH Key Detection Test"
echo "========================================="
echo ""

# Check if LinMon is running
if ! systemctl is-active --quiet linmond 2>/dev/null; then
    echo -e "${RED}ERROR: LinMon is not running${NC}"
    echo "Start LinMon with: sudo systemctl start linmond"
    exit 1
fi

# Check if monitor_cred_read is enabled
if ! grep -q "^monitor_cred_read = true" /etc/linmon/linmon.conf 2>/dev/null; then
    echo -e "${YELLOW}WARNING: monitor_cred_read may not be enabled in /etc/linmon/linmon.conf${NC}"
    echo "Enable with: monitor_cred_read = true"
    echo ""
fi

# Get current line count of log file
LOG_FILE="/var/log/linmon/events.json"
if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}ERROR: Log file $LOG_FILE not found${NC}"
    exit 1
fi

INITIAL_LINES=$(wc -l < "$LOG_FILE")

echo "Test 1: SSH Private Key Read Detection"
echo "----------------------------------------"

# Ensure .ssh directory exists
mkdir -p ~/.ssh
chmod 700 ~/.ssh

# Create a test SSH key if it doesn't exist
TEST_KEY_FILE="$HOME/.ssh/test_linmon_id_rsa"
if [ ! -f "$TEST_KEY_FILE" ]; then
    echo "Creating test SSH key..."
    ssh-keygen -t rsa -b 2048 -f "$TEST_KEY_FILE" -N "" -C "linmon-test" >/dev/null 2>&1
fi

echo "Reading SSH private key: $TEST_KEY_FILE"
cat "$TEST_KEY_FILE" > /dev/null

# Wait for event to be logged
sleep 2

# Check if event was logged
echo "Checking for security_cred_read event with cred_file=ssh_private_key..."
NEW_EVENTS=$(tail -n +$((INITIAL_LINES + 1)) "$LOG_FILE" | grep '"type":"security_cred_read"' | grep '"cred_file":"ssh_private_key"' | head -1)

if [ -n "$NEW_EVENTS" ]; then
    echo -e "${GREEN}✓ SSH private key read detected!${NC}"
    echo "Event: $(echo "$NEW_EVENTS" | jq -c '{type, cred_file, path, comm, username}')"
else
    echo -e "${RED}✗ SSH private key read NOT detected${NC}"
    echo "Check that monitor_cred_read=true in /etc/linmon/linmon.conf"
fi

echo ""
echo "Test 2: SSH Authorized Keys Write Detection"
echo "---------------------------------------------"

# Update initial line count
INITIAL_LINES=$(wc -l < "$LOG_FILE")

AUTH_KEYS_FILE="$HOME/.ssh/authorized_keys"
echo "Writing to authorized_keys: $AUTH_KEYS_FILE"

# Append a test key
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0LinMonTest linmon-test" >> "$AUTH_KEYS_FILE"

# Wait for event to be logged
sleep 2

# Check if event was logged
echo "Checking for security_cred_read event with cred_file=ssh_authorized_keys..."
NEW_EVENTS=$(tail -n +$((INITIAL_LINES + 1)) "$LOG_FILE" | grep '"type":"security_cred_read"' | grep '"cred_file":"ssh_authorized_keys"' | head -1)

if [ -n "$NEW_EVENTS" ]; then
    echo -e "${GREEN}✓ SSH authorized_keys write detected!${NC}"
    echo "Event: $(echo "$NEW_EVENTS" | jq -c '{type, cred_file, path, comm, username}')"
else
    echo -e "${RED}✗ SSH authorized_keys write NOT detected${NC}"
    echo "Check that monitor_cred_read=true in /etc/linmon/linmon.conf"
fi

echo ""
echo "Test 3: SSH Config Read Detection"
echo "-----------------------------------"

# Update initial line count
INITIAL_LINES=$(wc -l < "$LOG_FILE")

SSH_CONFIG_FILE="$HOME/.ssh/config"
echo "Reading SSH config: $SSH_CONFIG_FILE"

# Create/read SSH config
touch "$SSH_CONFIG_FILE"
chmod 600 "$SSH_CONFIG_FILE"
cat "$SSH_CONFIG_FILE" > /dev/null

# Wait for event to be logged
sleep 2

# Check if event was logged
echo "Checking for security_cred_read event with cred_file=ssh_user_config..."
NEW_EVENTS=$(tail -n +$((INITIAL_LINES + 1)) "$LOG_FILE" | grep '"type":"security_cred_read"' | grep '"cred_file":"ssh_user_config"' | head -1)

if [ -n "$NEW_EVENTS" ]; then
    echo -e "${GREEN}✓ SSH config read detected!${NC}"
    echo "Event: $(echo "$NEW_EVENTS" | jq -c '{type, cred_file, path, comm, username}')"
else
    echo -e "${RED}✗ SSH config read NOT detected${NC}"
    echo "Check that monitor_cred_read=true in /etc/linmon/linmon.conf"
fi

echo ""
echo "Cleanup"
echo "-------"

# Remove test artifacts
echo "Removing test SSH key: $TEST_KEY_FILE"
rm -f "$TEST_KEY_FILE" "$TEST_KEY_FILE.pub"

# Remove test entry from authorized_keys
if [ -f "$AUTH_KEYS_FILE" ]; then
    echo "Removing test entry from authorized_keys"
    sed -i '/linmon-test/d' "$AUTH_KEYS_FILE"
fi

echo ""
echo "========================================="
echo "Test complete!"
echo "========================================="
echo ""
echo "Review full events with:"
echo "  sudo tail -20 /var/log/linmon/events.json | jq 'select(.type == \"security_cred_read\" and (.cred_file | test(\"ssh\")))'"
echo ""
echo "Enable monitoring in /etc/linmon/linmon.conf:"
echo "  monitor_cred_read = true  # Already enabled by default"
