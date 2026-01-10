#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
# LinMon Activity Report Generator
#
# Generates human-readable reports from LinMon JSON event logs

set -euo pipefail

# Default values
LOG_FILE="/var/log/linmon/events.json"
OUTPUT_FORMAT="text"
TIME_FILTER=""
USER_FILTER=""
EVENT_TYPE_FILTER=""
SHOW_SECURITY_ONLY=false
LIMIT=""
REVERSE=false

# Color codes for terminal output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Generate human-readable activity reports from LinMon logs.

OPTIONS:
    -f, --file FILE         Log file to analyze (default: /var/log/linmon/events.json)
    -t, --time MINUTES      Only show events from last N minutes
    -u, --user USERNAME     Filter by username
    -e, --event TYPE        Filter by event type (process_exec, net_connect_tcp, etc.)
    -s, --security-only     Show only security-related events
    -n, --limit N           Limit output to N events
    -r, --reverse           Show newest events first
    -o, --format FORMAT     Output format: text (default), json, csv
    -h, --help              Show this help message

EXAMPLES:
    # Summary of all activity
    sudo $(basename "$0")

    # Security events from last hour
    sudo $(basename "$0") --time 60 --security-only

    # Network activity for specific user
    sudo $(basename "$0") --user alice --event net_connect_tcp

    # Recent process executions (newest first)
    sudo $(basename "$0") --event process_exec --limit 20 --reverse

EVENT TYPES:
    process_exec, process_exit          - Process lifecycle
    net_connect_tcp, net_accept_tcp     - TCP networking
    net_connect_udp, net_vsock_connect  - UDP/vsock networking
    priv_setuid, priv_setgid            - Privilege changes
    security_ptrace, security_memfd     - Security events
    security_cred_read, security_suid   - Credential/SUID events
    security_persistence, raw_disk_access - Persistence/disk access

EOF
    exit 0
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--file)
            LOG_FILE="$2"
            shift 2
            ;;
        -t|--time)
            TIME_FILTER="$2"
            shift 2
            ;;
        -u|--user)
            USER_FILTER="$2"
            shift 2
            ;;
        -e|--event)
            EVENT_TYPE_FILTER="$2"
            shift 2
            ;;
        -s|--security-only)
            SHOW_SECURITY_ONLY=true
            shift
            ;;
        -n|--limit)
            LIMIT="$2"
            shift 2
            ;;
        -r|--reverse)
            REVERSE=true
            shift
            ;;
        -o|--format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Check if log file exists
if [[ ! -f "$LOG_FILE" ]]; then
    echo "Error: Log file not found: $LOG_FILE" >&2
    exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed. Install with: sudo apt-get install jq" >&2
    exit 1
fi

# Build jq filter
JQ_FILTER="."

# Time filter (last N minutes)
if [[ -n "$TIME_FILTER" ]]; then
    cutoff=$(date -u -d "$TIME_FILTER minutes ago" '+%Y-%m-%dT%H:%M:%S')
    JQ_FILTER="$JQ_FILTER | select(.timestamp >= \"$cutoff\")"
fi

# User filter
if [[ -n "$USER_FILTER" ]]; then
    JQ_FILTER="$JQ_FILTER | select(.username == \"$USER_FILTER\")"
fi

# Event type filter
if [[ -n "$EVENT_TYPE_FILTER" ]]; then
    JQ_FILTER="$JQ_FILTER | select(.type == \"$EVENT_TYPE_FILTER\")"
fi

# Security-only filter
if [[ "$SHOW_SECURITY_ONLY" == true ]]; then
    JQ_FILTER="$JQ_FILTER | select(.type | startswith(\"security_\") or startswith(\"priv_\") or . == \"raw_disk_access\")"
fi

# Reverse order (newest first)
SORT_CMD="cat"
if [[ "$REVERSE" == true ]]; then
    SORT_CMD="tac"
fi

# Apply limit
LIMIT_CMD="cat"
if [[ -n "$LIMIT" ]]; then
    LIMIT_CMD="head -n $LIMIT"
fi

# Count events by type
count_events() {
    echo -e "${BOLD}Event Type Summary${NC}"
    echo "=================="
    grep '^{' "$LOG_FILE" | $SORT_CMD | jq -r "$JQ_FILTER | .type" 2>/dev/null | sort | uniq -c | sort -rn | while read count type; do
        printf "%6d  %s\n" "$count" "$type"
    done
    echo
}

# Count events by user
count_users() {
    echo -e "${BOLD}Activity by User${NC}"
    echo "================"
    grep '^{' "$LOG_FILE" | $SORT_CMD | jq -r "$JQ_FILTER | .username // \"unknown\"" 2>/dev/null | sort | uniq -c | sort -rn | head -20 | while read count user; do
        printf "%6d  %s\n" "$count" "$user"
    done
    echo
}

# Show security events
show_security_events() {
    echo -e "${BOLD}${RED}Security Events${NC}"
    echo "==============="

    grep '^{' "$LOG_FILE" | $SORT_CMD | jq -c "$JQ_FILTER | select(.type | startswith(\"security_\") or . == \"raw_disk_access\")" 2>/dev/null | $LIMIT_CMD | while IFS= read -r line; do
        timestamp=$(echo "$line" | jq -r '.timestamp')
        type=$(echo "$line" | jq -r '.type')
        user=$(echo "$line" | jq -r '.username // "unknown"')
        pid=$(echo "$line" | jq -r '.pid')

        case "$type" in
            security_ptrace)
                target_pid=$(echo "$line" | jq -r '.target_pid')
                echo -e "${RED}[$(date -d "$timestamp" '+%H:%M:%S')] PTRACE: $user (PID $pid) attached to PID $target_pid${NC}"
                ;;
            security_memfd)
                fd_name=$(echo "$line" | jq -r '.fd_name')
                echo -e "${RED}[$(date -d "$timestamp" '+%H:%M:%S')] MEMFD: $user (PID $pid) created in-memory file: $fd_name${NC}"
                ;;
            security_cred_read)
                cred_file=$(echo "$line" | jq -r '.cred_file')
                echo -e "${RED}[$(date -d "$timestamp" '+%H:%M:%S')] CRED_READ: $user (PID $pid) accessed: $cred_file${NC}"
                ;;
            security_suid)
                filename=$(echo "$line" | jq -r '.filename')
                echo -e "${RED}[$(date -d "$timestamp" '+%H:%M:%S')] SUID_EXEC: $user (PID $pid) executed: $filename${NC}"
                ;;
            security_persistence)
                persist_file=$(echo "$line" | jq -r '.persist_file')
                persist_type=$(echo "$line" | jq -r '.persist_type')
                echo -e "${RED}[$(date -d "$timestamp" '+%H:%M:%S')] PERSISTENCE: $user (PID $pid) modified $persist_type: $persist_file${NC}"
                ;;
            raw_disk_access)
                device=$(echo "$line" | jq -r '.device')
                echo -e "${RED}[$(date -d "$timestamp" '+%H:%M:%S')] DISK_ACCESS: $user (PID $pid) wrote to raw device: $device${NC}"
                ;;
            *)
                echo -e "${YELLOW}[$(date -d "$timestamp" '+%H:%M:%S')] $type: $user (PID $pid)${NC}"
                ;;
        esac
    done
    echo
}

# Show privilege escalations
show_privilege_events() {
    echo -e "${BOLD}${YELLOW}Privilege Changes${NC}"
    echo "================="

    grep '^{' "$LOG_FILE" | $SORT_CMD | jq -c "$JQ_FILTER | select(.type | startswith(\"priv_\"))" 2>/dev/null | $LIMIT_CMD | while IFS= read -r line; do
        timestamp=$(echo "$line" | jq -r '.timestamp')
        type=$(echo "$line" | jq -r '.type')
        user=$(echo "$line" | jq -r '.username // "unknown"')
        pid=$(echo "$line" | jq -r '.pid')
        new_uid=$(echo "$line" | jq -r '.new_uid // empty')
        new_gid=$(echo "$line" | jq -r '.new_gid // empty')

        if [[ "$type" == "priv_setuid" ]]; then
            echo -e "${YELLOW}[$(date -d "$timestamp" '+%H:%M:%S')] SETUID: $user (PID $pid) → UID $new_uid${NC}"
        elif [[ "$type" == "priv_setgid" ]]; then
            echo -e "${YELLOW}[$(date -d "$timestamp" '+%H:%M:%S')] SETGID: $user (PID $pid) → GID $new_gid${NC}"
        fi
    done
    echo
}

# Show network connections
show_network_events() {
    echo -e "${BOLD}${BLUE}Network Connections${NC}"
    echo "==================="

    grep '^{' "$LOG_FILE" | $SORT_CMD | jq -c "$JQ_FILTER | select(.type | startswith(\"net_\"))" 2>/dev/null | $LIMIT_CMD | while IFS= read -r line; do
        timestamp=$(echo "$line" | jq -r '.timestamp')
        type=$(echo "$line" | jq -r '.type')
        user=$(echo "$line" | jq -r '.username // "unknown"')
        pid=$(echo "$line" | jq -r '.pid')
        comm=$(echo "$line" | jq -r '.comm')

        case "$type" in
            net_connect_tcp|net_accept_tcp)
                dest_ip=$(echo "$line" | jq -r '.dest_ip // .remote_ip // "unknown"')
                dest_port=$(echo "$line" | jq -r '.dest_port // .remote_port // "unknown"')

                if [[ "$type" == "net_connect_tcp" ]]; then
                    echo -e "${BLUE}[$(date -d "$timestamp" '+%H:%M:%S')] TCP_CONNECT: $comm ($user) → $dest_ip:$dest_port${NC}"
                else
                    echo -e "${BLUE}[$(date -d "$timestamp" '+%H:%M:%S')] TCP_ACCEPT: $comm ($user) ← $dest_ip:$dest_port${NC}"
                fi
                ;;
            net_vsock_connect)
                dest_cid=$(echo "$line" | jq -r '.dest_cid')
                dest_port=$(echo "$line" | jq -r '.dest_port')
                echo -e "${CYAN}[$(date -d "$timestamp" '+%H:%M:%S')] VSOCK: $comm ($user) → CID $dest_cid:$dest_port${NC}"
                ;;
        esac
    done
    echo
}

# Show process executions
show_process_events() {
    echo -e "${BOLD}${GREEN}Process Executions${NC}"
    echo "==================="

    grep '^{' "$LOG_FILE" | $SORT_CMD | jq -c "$JQ_FILTER | select(.type == \"process_exec\")" 2>/dev/null | $LIMIT_CMD | while IFS= read -r line; do
        timestamp=$(echo "$line" | jq -r '.timestamp')
        user=$(echo "$line" | jq -r '.username // "unknown"')
        pid=$(echo "$line" | jq -r '.pid')
        filename=$(echo "$line" | jq -r '.filename')
        cmdline=$(echo "$line" | jq -r '.cmdline // ""')

        # Truncate long command lines
        if [[ ${#cmdline} -gt 80 ]]; then
            cmdline="${cmdline:0:77}..."
        fi

        echo -e "${GREEN}[$(date -d "$timestamp" '+%H:%M:%S')] EXEC: $user (PID $pid) $filename${NC}"
        if [[ -n "$cmdline" ]]; then
            echo "       $cmdline"
        fi
    done
    echo
}

# Generate summary report
generate_summary() {
    echo -e "${BOLD}LinMon Activity Report${NC}"
    echo "======================"
    echo "Log file: $LOG_FILE"
    echo "Generated: $(date)"
    echo

    # Total event count
    total=$(grep '^{' "$LOG_FILE" | jq -r "$JQ_FILTER" 2>/dev/null | wc -l)
    echo -e "Total events: ${BOLD}$total${NC}"
    echo

    count_events
    count_users
    show_security_events
    show_privilege_events
    show_network_events
    show_process_events
}

# Output formats
case "$OUTPUT_FORMAT" in
    text)
        generate_summary
        ;;
    json)
        grep '^{' "$LOG_FILE" | $SORT_CMD | jq -c "$JQ_FILTER" 2>/dev/null | $LIMIT_CMD
        ;;
    csv)
        echo "timestamp,type,username,pid,details"
        grep '^{' "$LOG_FILE" | $SORT_CMD | jq -r "$JQ_FILTER | [.timestamp, .type, .username // \"unknown\", .pid, (.cmdline // .filename // .device // \"\")] | @csv" 2>/dev/null | $LIMIT_CMD
        ;;
    *)
        echo "Error: Unknown output format: $OUTPUT_FORMAT" >&2
        exit 1
        ;;
esac
