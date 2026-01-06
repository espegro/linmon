#!/bin/bash
# Test script for LinMon persistence mechanism detection (T1053, T1547)
# Tests EVENT_SECURITY_PERSISTENCE

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "LinMon Persistence Detection Test"
echo "========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}WARNING: Some tests require root privileges${NC}"
    echo "Run with: sudo $0"
    echo "Continuing with user-level tests only..."
    echo ""
    ROOT_TESTS=false
else
    ROOT_TESTS=true
fi

# Check if LinMon is running
if ! systemctl is-active --quiet linmond 2>/dev/null; then
    echo -e "${RED}ERROR: LinMon is not running${NC}"
    echo "Start LinMon with: sudo systemctl start linmond"
    exit 1
fi

# Check if monitor_persistence is enabled
if ! grep -q "^monitor_persistence = true" /etc/linmon/linmon.conf 2>/dev/null; then
    echo -e "${YELLOW}WARNING: monitor_persistence is not enabled in /etc/linmon/linmon.conf${NC}"
    echo "Enable with: monitor_persistence = true"
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

# Test 1: Cron Persistence (requires root)
if [ "$ROOT_TESTS" = true ]; then
    echo "Test 1: Cron Persistence Detection"
    echo "------------------------------------"

    CRON_FILE="/etc/cron.d/linmon_test"
    echo "Creating cron job: $CRON_FILE"
    echo "# LinMon test cron job" > "$CRON_FILE"
    echo "* * * * * root /bin/true" >> "$CRON_FILE"

    # Wait for event to be logged
    sleep 2

    # Check if event was logged
    echo "Checking for security_persistence event with persistence_type=cron..."
    NEW_EVENTS=$(tail -n +$((INITIAL_LINES + 1)) "$LOG_FILE" | grep '"type":"security_persistence"' | grep '"persistence_type":"cron"' | head -1)

    if [ -n "$NEW_EVENTS" ]; then
        echo -e "${GREEN}✓ Cron persistence detected!${NC}"
        echo "Event: $(echo "$NEW_EVENTS" | jq -c '{type, persistence_type, path, comm, username}')"
    else
        echo -e "${RED}✗ Cron persistence NOT detected${NC}"
        echo "Check that monitor_persistence=true in /etc/linmon/linmon.conf"
    fi

    # Update initial line count
    INITIAL_LINES=$(wc -l < "$LOG_FILE")
    echo ""
fi

# Test 2: Shell Profile Persistence
echo "Test 2: Shell Profile Persistence Detection"
echo "---------------------------------------------"

# Update initial line count if we skipped test 1
if [ "$ROOT_TESTS" = false ]; then
    INITIAL_LINES=$(wc -l < "$LOG_FILE")
fi

BASHRC_FILE="$HOME/.bashrc"
echo "Appending to shell profile: $BASHRC_FILE"
echo "# LinMon test entry" >> "$BASHRC_FILE"
echo "export LINMON_TEST=1" >> "$BASHRC_FILE"

# Wait for event to be logged
sleep 2

# Check if event was logged
echo "Checking for security_persistence event with persistence_type=shell_profile..."
NEW_EVENTS=$(tail -n +$((INITIAL_LINES + 1)) "$LOG_FILE" | grep '"type":"security_persistence"' | grep '"persistence_type":"shell_profile"' | head -1)

if [ -n "$NEW_EVENTS" ]; then
    echo -e "${GREEN}✓ Shell profile persistence detected!${NC}"
    echo "Event: $(echo "$NEW_EVENTS" | jq -c '{type, persistence_type, path, comm, username}')"
else
    echo -e "${RED}✗ Shell profile persistence NOT detected${NC}"
    echo "Check that monitor_persistence=true in /etc/linmon/linmon.conf"
fi

# Update initial line count
INITIAL_LINES=$(wc -l < "$LOG_FILE")

echo ""

# Test 3: Systemd Service Persistence (requires root)
if [ "$ROOT_TESTS" = true ]; then
    echo "Test 3: Systemd Service Persistence Detection"
    echo "-----------------------------------------------"

    SYSTEMD_FILE="/etc/systemd/system/linmon-test.service"
    echo "Creating systemd service: $SYSTEMD_FILE"
    cat > "$SYSTEMD_FILE" <<'EOF'
[Unit]
Description=LinMon Test Service

[Service]
Type=oneshot
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
EOF

    # Wait for event to be logged
    sleep 2

    # Check if event was logged
    echo "Checking for security_persistence event with persistence_type=systemd..."
    NEW_EVENTS=$(tail -n +$((INITIAL_LINES + 1)) "$LOG_FILE" | grep '"type":"security_persistence"' | grep '"persistence_type":"systemd"' | head -1)

    if [ -n "$NEW_EVENTS" ]; then
        echo -e "${GREEN}✓ Systemd persistence detected!${NC}"
        echo "Event: $(echo "$NEW_EVENTS" | jq -c '{type, persistence_type, path, comm, username}')"
    else
        echo -e "${RED}✗ Systemd persistence NOT detected${NC}"
        echo "Check that monitor_persistence=true in /etc/linmon/linmon.conf"
    fi

    # Update initial line count
    INITIAL_LINES=$(wc -l < "$LOG_FILE")
    echo ""
fi

# Test 4: Autostart Persistence
echo "Test 4: Autostart Persistence Detection"
echo "-----------------------------------------"

AUTOSTART_DIR="$HOME/.config/autostart"
AUTOSTART_FILE="$AUTOSTART_DIR/linmon-test.desktop"

mkdir -p "$AUTOSTART_DIR"
echo "Creating autostart entry: $AUTOSTART_FILE"
cat > "$AUTOSTART_FILE" <<'EOF'
[Desktop Entry]
Type=Application
Name=LinMon Test
Exec=/bin/true
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
EOF

# Wait for event to be logged
sleep 2

# Check if event was logged
echo "Checking for security_persistence event with persistence_type=autostart..."
NEW_EVENTS=$(tail -n +$((INITIAL_LINES + 1)) "$LOG_FILE" | grep '"type":"security_persistence"' | grep '"persistence_type":"autostart"' | head -1)

if [ -n "$NEW_EVENTS" ]; then
    echo -e "${GREEN}✓ Autostart persistence detected!${NC}"
    echo "Event: $(echo "$NEW_EVENTS" | jq -c '{type, persistence_type, path, comm, username}')"
else
    echo -e "${RED}✗ Autostart persistence NOT detected${NC}"
    echo "Check that monitor_persistence=true in /etc/linmon/linmon.conf"
fi

echo ""
echo "Cleanup"
echo "-------"

# Remove test artifacts
if [ "$ROOT_TESTS" = true ]; then
    echo "Removing cron job: $CRON_FILE"
    rm -f "$CRON_FILE"

    echo "Removing systemd service: $SYSTEMD_FILE"
    rm -f "$SYSTEMD_FILE"
    systemctl daemon-reload 2>/dev/null || true
fi

echo "Removing shell profile test entries..."
sed -i '/# LinMon test entry/d' "$BASHRC_FILE"
sed -i '/LINMON_TEST/d' "$BASHRC_FILE"

echo "Removing autostart entry: $AUTOSTART_FILE"
rm -f "$AUTOSTART_FILE"

echo ""
echo "========================================="
echo "Test complete!"
echo "========================================="
echo ""
echo "Review full events with:"
echo "  sudo tail -20 /var/log/linmon/events.json | jq 'select(.type == \"security_persistence\")'"
echo ""
echo "Enable monitoring in /etc/linmon/linmon.conf:"
echo "  monitor_persistence = true  # T1053, T1547 persistence detection"
echo "Then reload: sudo systemctl reload linmond"
