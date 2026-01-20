#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# LinMon Watchdog - Monitors linmond health and alerts on issues
# Run via systemd timer (every 5 minutes) or cron

set -euo pipefail

# Configuration
LINMOND_SERVICE="linmond.service"
LINMOND_BINARY="/usr/local/sbin/linmond"
LINMOND_CONFIG="/etc/linmon/linmon.conf"
LOG_FILE="/var/log/linmon/events.json"
MAX_AGE_SECONDS=300  # Alert if no events for 5 minutes
ALERT_EMAIL=""  # Optional: email for alerts

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Alert function
alert() {
    local severity=$1
    local message=$2

    echo -e "${RED}[ALERT]${NC} $severity: $message" >&2
    logger -t linmon-watchdog -p daemon.err "$severity: $message"

    # Optional: send email alert
    if [[ -n "$ALERT_EMAIL" ]]; then
        echo "$message" | mail -s "LinMon Alert: $severity" "$ALERT_EMAIL"
    fi

    # Log to syslog for SIEM integration
    logger -t linmon-watchdog -p daemon.alert "severity=$severity message=\"$message\""
}

# Check 1: Service is running
check_service_running() {
    if ! systemctl is-active --quiet "$LINMOND_SERVICE"; then
        alert "CRITICAL" "linmond service is not running"
        return 1
    fi
    echo -e "${GREEN}✓${NC} Service running"
    return 0
}

# Check 2: Process is alive
check_process_alive() {
    if ! pgrep -x linmond > /dev/null; then
        alert "CRITICAL" "linmond process not found (systemd unit may be stale)"
        return 1
    fi
    echo -e "${GREEN}✓${NC} Process alive"
    return 0
}

# Check 3: Events are being logged
check_events_recent() {
    if [[ ! -f "$LOG_FILE" ]]; then
        alert "CRITICAL" "Log file $LOG_FILE does not exist"
        return 1
    fi

    # Get timestamp of last event
    local last_event_time
    last_event_time=$(stat -c %Y "$LOG_FILE" 2>/dev/null || echo 0)
    local current_time
    current_time=$(date +%s)
    local age=$((current_time - last_event_time))

    if [[ $age -gt $MAX_AGE_SECONDS ]]; then
        alert "WARNING" "No events logged for $age seconds (threshold: $MAX_AGE_SECONDS)"
        return 1
    fi

    echo -e "${GREEN}✓${NC} Events logged recently (${age}s ago)"
    return 0
}

# Check 4: Immutable flags set (tamper detection)
check_immutable_flags() {
    local issues=0

    # Check binary immutable flag
    if ! lsattr "$LINMOND_BINARY" 2>/dev/null | grep -q '^....i'; then
        alert "WARNING" "Immutable flag removed from $LINMOND_BINARY (possible tampering)"
        ((issues++))
    fi

    # Check config immutable flag
    if ! lsattr "$LINMOND_CONFIG" 2>/dev/null | grep -q '^....i'; then
        alert "WARNING" "Immutable flag removed from $LINMOND_CONFIG (possible tampering)"
        ((issues++))
    fi

    if [[ $issues -eq 0 ]]; then
        echo -e "${GREEN}✓${NC} Immutable flags set"
        return 0
    else
        return 1
    fi
}

# Check 5: Binary integrity (checksum)
check_binary_integrity() {
    # Get expected checksum from systemd checkpoint logs
    local expected_hash
    expected_hash=$(journalctl -u "$LINMOND_SERVICE" --no-pager | \
                    grep "daemon_start\|daemon_checkpoint" | \
                    tail -1 | \
                    grep -oP 'daemon_sha256=\K[a-f0-9]{64}' || echo "")

    if [[ -z "$expected_hash" ]]; then
        echo -e "${YELLOW}⚠${NC} No baseline checksum found (first run?)"
        return 0
    fi

    # Calculate current checksum
    local current_hash
    current_hash=$(sha256sum "$LINMOND_BINARY" | awk '{print $1}')

    if [[ "$current_hash" != "$expected_hash" ]]; then
        alert "CRITICAL" "Binary checksum mismatch! Expected: $expected_hash, Got: $current_hash (possible rootkit)"
        return 1
    fi

    echo -e "${GREEN}✓${NC} Binary integrity verified"
    return 0
}

# Check 6: Memory usage reasonable
check_memory_usage() {
    local mem_limit_mb=512
    local mem_usage_mb
    mem_usage_mb=$(systemctl show "$LINMOND_SERVICE" --property=MemoryCurrent | \
                   awk -F= '{print int($2/1024/1024)}')

    if [[ $mem_usage_mb -gt $mem_limit_mb ]]; then
        alert "WARNING" "Memory usage high: ${mem_usage_mb}MB (limit: ${mem_limit_mb}MB)"
        return 1
    fi

    echo -e "${GREEN}✓${NC} Memory usage normal (${mem_usage_mb}MB)"
    return 0
}

# Main
main() {
    echo "=== LinMon Watchdog Check ==="
    echo "Time: $(date)"
    echo ""

    local failed=0

    check_service_running || ((failed++))
    check_process_alive || ((failed++))
    check_events_recent || ((failed++))
    check_immutable_flags || ((failed++))
    check_binary_integrity || ((failed++))
    check_memory_usage || ((failed++))

    echo ""
    if [[ $failed -eq 0 ]]; then
        echo -e "${GREEN}All checks passed${NC}"
        exit 0
    else
        echo -e "${RED}$failed check(s) failed${NC}"
        exit 1
    fi
}

main
