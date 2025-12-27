#!/bin/bash
# LinMon Daily Report - Summary statistics from last 24 hours
# Usage: ./daily-report.sh [hours] [log_dir]
#   hours: Number of hours to analyze (default: 24)
#   log_dir: Path to log directory (default: /var/log/linmon)

set -euo pipefail

# Configuration
HOURS="${1:-24}"
LOG_DIR="${2:-/var/log/linmon}"
EVENTS_JSON="${LOG_DIR}/events.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check dependencies
if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required. Install with: sudo apt-get install jq" >&2
    exit 1
fi

# Check if log files exist
if [ ! -f "$EVENTS_JSON" ]; then
    echo "Error: Log file not found: $EVENTS_JSON" >&2
    exit 1
fi

# Calculate timestamp for N hours ago
CUTOFF_TIME=$(date -d "${HOURS} hours ago" -u +"%Y-%m-%dT%H:%M:%S")

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}    LinMon Daily Report - Last ${HOURS} Hours${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "Report generated: $(date)"
echo "Time range: ${CUTOFF_TIME}Z to $(date -u +"%Y-%m-%dT%H:%M:%S")Z"
echo "Log directory: ${LOG_DIR}"
echo ""

# Function to read all events (current + rotated logs)
read_all_events() {
    # Read current log + all rotated logs, filter by timestamp
    (cat "$EVENTS_JSON" 2>/dev/null || true
     for f in "${LOG_DIR}"/events.json.[0-9]*; do
         [ -f "$f" ] && cat "$f" || true
     done) | jq -c "select(.timestamp >= \"${CUTOFF_TIME}\")"
}

# Event counts by type
echo -e "${GREEN}Event Summary by Type:${NC}"
echo "────────────────────────────────────────────────────────"
read_all_events | jq -r '.type' | sort | uniq -c | sort -rn | awk '{printf "  %-30s %8d\n", $2, $1}'
echo ""

# Total event count
TOTAL_EVENTS=$(read_all_events | wc -l)
echo -e "${GREEN}Total Events:${NC} ${TOTAL_EVENTS}"
echo ""

# Top 10 most active users
echo -e "${GREEN}Top 10 Most Active Users:${NC}"
echo "────────────────────────────────────────────────────────"
read_all_events | jq -r 'select(.username) | .username' | sort | uniq -c | sort -rn | head -10 | awk '{printf "  %-30s %8d events\n", $2, $1}'
echo ""

# Top 10 most executed processes
echo -e "${GREEN}Top 10 Most Executed Processes:${NC}"
echo "────────────────────────────────────────────────────────"
read_all_events | jq -r 'select(.type == "process_exec") | .process_name // .comm' | sort | uniq -c | sort -rn | head -10 | awk '{printf "  %-30s %8d executions\n", $2, $1}'
echo ""

# Network activity summary
TCP_CONNECT=$(read_all_events | jq -r 'select(.type == "net_connect_tcp")' | wc -l)
TCP_ACCEPT=$(read_all_events | jq -r 'select(.type == "net_accept_tcp")' | wc -l)
UDP_SEND=$(read_all_events | jq -r 'select(.type == "net_send_udp")' | wc -l)

echo -e "${GREEN}Network Activity:${NC}"
echo "────────────────────────────────────────────────────────"
echo "  TCP connections (outbound): ${TCP_CONNECT}"
echo "  TCP accepts (inbound):      ${TCP_ACCEPT}"
echo "  UDP sends:                  ${UDP_SEND}"
echo ""

# Top 10 network destinations
echo -e "${GREEN}Top 10 Network Destinations:${NC}"
echo "────────────────────────────────────────────────────────"
read_all_events | jq -r 'select(.type == "net_connect_tcp") | .daddr' | sort | uniq -c | sort -rn | head -10 | awk '{printf "  %-40s %8d connections\n", $2, $1}'
echo ""

# Security events
SECURITY_COUNT=$(read_all_events | jq -r 'select(.type | startswith("security_"))' | wc -l)

if [ "$SECURITY_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠ Security Events Detected: ${SECURITY_COUNT}${NC}"
    echo "────────────────────────────────────────────────────────"
    read_all_events | jq -r 'select(.type | startswith("security_")) | .type' | sort | uniq -c | sort -rn | awk '{printf "  %-40s %8d\n", $2, $1}'
    echo ""
fi

# Privilege escalation events
PRIV_SUDO=$(read_all_events | jq -r 'select(.type == "priv_sudo")' | wc -l)
PRIV_SETUID=$(read_all_events | jq -r 'select(.type == "priv_setuid")' | wc -l)

if [ "$PRIV_SUDO" -gt 0 ] || [ "$PRIV_SETUID" -gt 0 ]; then
    echo -e "${GREEN}Privilege Escalation:${NC}"
    echo "────────────────────────────────────────────────────────"
    echo "  sudo executions:  ${PRIV_SUDO}"
    echo "  setuid calls:     ${PRIV_SETUID}"
    echo ""
fi

# File activity summary
FILE_CREATE=$(read_all_events | jq -r 'select(.type == "file_create")' | wc -l)
FILE_DELETE=$(read_all_events | jq -r 'select(.type == "file_delete")' | wc -l)
FILE_MODIFY=$(read_all_events | jq -r 'select(.type == "file_modify")' | wc -l)

if [ "$FILE_CREATE" -gt 0 ] || [ "$FILE_DELETE" -gt 0 ] || [ "$FILE_MODIFY" -gt 0 ]; then
    echo -e "${GREEN}File Activity:${NC}"
    echo "────────────────────────────────────────────────────────"
    echo "  Files created:  ${FILE_CREATE}"
    echo "  Files deleted:  ${FILE_DELETE}"
    echo "  Files modified: ${FILE_MODIFY}"
    echo ""
fi

# Smart tamper detection - ignore daemon restarts, only flag suspicious gaps
echo -e "${GREEN}Tamper Detection:${NC}"
echo "────────────────────────────────────────────────────────"

# Get daemon start events to identify session boundaries
DAEMON_STARTS=$(read_all_events | jq -r 'select(.type == "daemon_start")' | wc -l)

# Check for sequence gaps within sessions
# Strategy: Large jumps (>100) are daemon restarts (expected), small gaps are suspicious (tampering)
SUSPICIOUS_GAPS=$(read_all_events | jq -r 'select(.seq) | .seq' | sort -n | awk '
    NR > 1 && $1 != prev + 1 {
        gap_size = $1 - prev - 1
        # Only report gaps < 100 (likely tampering, not daemon restart)
        if (gap_size < 100 && gap_size > 0) {
            suspicious++
            print "  Gap: seq " prev+1 " to " ($1-1) " (" gap_size " events missing)"
        }
    }
    {prev = $1}
    END {
        if (suspicious > 0) {
            print "SUSPICIOUS"
        } else {
            print "CLEAN"
        }
    }
')

if echo "$SUSPICIOUS_GAPS" | grep -q "SUSPICIOUS"; then
    echo -e "  ${RED}⚠ WARNING: Suspicious sequence gaps detected!${NC}"
    echo "$SUSPICIOUS_GAPS" | grep "^  Gap:"
    echo "  These gaps suggest deleted events (tampering)."
    if [ "$DAEMON_STARTS" -gt 1 ]; then
        echo "  Note: $DAEMON_STARTS daemon restarts in time range (expected sequence resets ignored)."
    fi
elif [ "$DAEMON_STARTS" -gt 1 ]; then
    echo -e "  ${GREEN}✓ No suspicious gaps detected${NC}"
    echo "  $DAEMON_STARTS daemon restarts in time range (sequence resets are normal)."
else
    echo -e "  ${GREEN}✓ No sequence gaps detected - log integrity OK${NC}"
fi
echo ""

# Events per hour (last 24 hours)
echo -e "${GREEN}Events Per Hour (Last 24h):${NC}"
echo "────────────────────────────────────────────────────────"
read_all_events | jq -r '.timestamp | split("T")[1] | split(":")[0]' | sort | uniq -c | awk '{printf "  Hour %s:00 - %8d events\n", $2, $1}'
echo ""

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo "Report complete."
echo ""
