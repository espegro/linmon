#!/bin/bash
# LinMon Query Tool - Common analysis queries for LinMon event logs
# Usage: ./linmon-query.sh <command> [options]

set -euo pipefail

LOGFILE="${LINMON_LOG:-/var/log/linmon/events.json}"
LIMIT="${LINMON_LIMIT:-10}"

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed"
    echo "Install with: sudo apt-get install jq"
    exit 1
fi

# Check if log file exists
if [ ! -f "$LOGFILE" ]; then
    echo "Error: Log file not found: $LOGFILE"
    echo "Set LINMON_LOG environment variable to specify a different path"
    exit 1
fi

show_help() {
    cat <<EOF
LinMon Query Tool - Analyze LinMon event logs

Usage: $0 <command> [options]

COMMANDS:
  tail                   Show last $LIMIT events (pretty-printed JSON)
  follow                 Follow events in real-time
  stats                  Show event statistics
  users                  Show active users
  processes              Show most executed processes
  sudo                   Show all sudo usage
  sudo-user <username>   Show sudo usage by specific user
  priv-esc               Show all privilege escalation events
  network                Show network connections
  network-suspicious     Show suspicious network connections (non-standard ports)
  network-external       Show connections to external IPs (non-RFC1918)
  files                  Show file operations
  timeline <username>    Show timeline for specific user
  search <pattern>       Search for pattern in any field
  top-talkers            Show users by event count

ENVIRONMENT VARIABLES:
  LINMON_LOG             Path to log file (default: /var/log/linmon/events.json)
  LINMON_LIMIT           Number of results to show (default: 10)

EXAMPLES:
  $0 tail
  $0 follow
  $0 sudo-user alice
  $0 timeline bob
  LINMON_LIMIT=20 $0 processes
  $0 search "curl.*api.example.com"

For more queries and examples, see MONITORING.md
EOF
}

cmd_tail() {
    tail -n "$LIMIT" "$LOGFILE" | jq '.'
}

cmd_follow() {
    echo "Following events in real-time (Ctrl-C to stop)..."
    tail -f "$LOGFILE" | jq --unbuffered '.'
}

cmd_stats() {
    echo "=== LinMon Event Statistics ==="
    echo
    echo "Total events:"
    wc -l < "$LOGFILE"
    echo
    echo "Events by type:"
    jq -r '.type' "$LOGFILE" | sort | uniq -c | sort -rn
    echo
    echo "Events in last hour:"
    last_hour=$(date -d '1 hour ago' -Iseconds)
    jq -r 'select(.timestamp > "'"$last_hour"'") | .type' "$LOGFILE" | wc -l
}

cmd_users() {
    echo "=== Active Users (top $LIMIT) ==="
    jq -r '.username // "system"' "$LOGFILE" | \
        sort | uniq -c | sort -rn | head -n "$LIMIT" | \
        awk '{printf "%-10s %s\n", $1, $2}'
}

cmd_processes() {
    echo "=== Most Executed Processes (top $LIMIT) ==="
    grep '"type":"process_exec"' "$LOGFILE" | \
        jq -r '.comm' | \
        sort | uniq -c | sort -rn | head -n "$LIMIT" | \
        awk '{printf "%-10s %s\n", $1, $2}'
}

cmd_sudo() {
    echo "=== Sudo Usage (last $LIMIT) ==="
    grep '"type":"priv_sudo"' "$LOGFILE" | tail -n "$LIMIT" | \
        jq -r '[.timestamp, .old_username, .target // "unknown"] | @tsv' | \
        column -t -s $'\t' -N "Timestamp,User,Command"
}

cmd_sudo_user() {
    local user="$1"
    echo "=== Sudo Usage by $user (last $LIMIT) ==="
    grep '"type":"priv_sudo"' "$LOGFILE" | \
        jq -r 'select(.old_username == "'"$user"'") | [.timestamp, .target // "unknown"] | @tsv' | \
        tail -n "$LIMIT" | \
        column -t -s $'\t' -N "Timestamp,Command"
}

cmd_priv_esc() {
    echo "=== Privilege Escalation Events (last $LIMIT) ==="
    grep -E '"type":"priv_(setuid|setgid|sudo)"' "$LOGFILE" | tail -n "$LIMIT" | \
        jq -r '[.timestamp, .type, .old_username // .old_uid, .new_username // .new_uid, .comm] | @tsv' | \
        column -t -s $'\t' -N "Timestamp,Type,From,To,Process"
}

cmd_network() {
    echo "=== Network Connections (last $LIMIT) ==="
    grep -E '"type":"net_(connect|accept)_tcp"' "$LOGFILE" | tail -n "$LIMIT" | \
        jq -r '[.timestamp, .type, .comm, .saddr, .sport, .daddr, .dport] | @tsv' | \
        column -t -s $'\t' -N "Timestamp,Type,Process,Source,SPort,Dest,DPort"
}

cmd_network_suspicious() {
    echo "=== Suspicious Network Connections (non-standard ports, last $LIMIT) ==="
    grep '"type":"net_connect_tcp"' "$LOGFILE" | \
        jq -r 'select(.dport != 80 and .dport != 443 and .dport != 22 and .dport != 53) | [.timestamp, .comm, .username, .daddr, .dport] | @tsv' | \
        tail -n "$LIMIT" | \
        column -t -s $'\t' -N "Timestamp,Process,User,Dest,Port"
}

cmd_network_external() {
    echo "=== External Network Connections (non-RFC1918, last $LIMIT) ==="
    grep '"type":"net_connect_tcp"' "$LOGFILE" | \
        jq -r 'select(.daddr | test("^(?!10\\.|172\\.1[6-9]\\.|172\\.2[0-9]\\.|172\\.3[0-1]\\.|192\\.168\\.|127\\.).*")) | [.timestamp, .comm, .daddr, .dport] | @tsv' | \
        tail -n "$LIMIT" | \
        column -t -s $'\t' -N "Timestamp,Process,Dest,Port"
}

cmd_files() {
    echo "=== File Operations (last $LIMIT) ==="
    grep -E '"type":"file_(create|delete|modify)"' "$LOGFILE" | tail -n "$LIMIT" | \
        jq -r '[.timestamp, .type, .username, .comm, .filename] | @tsv' | \
        column -t -s $'\t' -N "Timestamp,Type,User,Process,File"
}

cmd_timeline() {
    local user="$1"
    echo "=== Activity Timeline for $user (last $LIMIT) ==="
    grep '"username":"'"$user"'"' "$LOGFILE" | tail -n "$LIMIT" | \
        jq -r '[.timestamp, .type, .comm, .cmdline // .filename // (.daddr + ":" + (.dport|tostring)) // ""] | @tsv' | \
        column -t -s $'\t' -N "Timestamp,Type,Process,Details"
}

cmd_search() {
    local pattern="$1"
    echo "=== Search Results for: $pattern (last $LIMIT) ==="
    grep -i -- "$pattern" "$LOGFILE" | tail -n "$LIMIT" | jq '.'
}

cmd_top_talkers() {
    echo "=== Top Event Generators (last 1000 events) ==="
    tail -n 1000 "$LOGFILE" | \
        jq -r '.username // "system"' | \
        sort | uniq -c | sort -rn | head -n "$LIMIT" | \
        awk '{printf "%5d events  %s\n", $1, $2}'
}

# Main command dispatcher
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

COMMAND="$1"
shift

case "$COMMAND" in
    tail)
        cmd_tail
        ;;
    follow)
        cmd_follow
        ;;
    stats)
        cmd_stats
        ;;
    users)
        cmd_users
        ;;
    processes)
        cmd_processes
        ;;
    sudo)
        cmd_sudo
        ;;
    sudo-user)
        if [ $# -eq 0 ]; then
            echo "Error: sudo-user requires username argument"
            echo "Usage: $0 sudo-user <username>"
            exit 1
        fi
        cmd_sudo_user "$1"
        ;;
    priv-esc)
        cmd_priv_esc
        ;;
    network)
        cmd_network
        ;;
    network-suspicious)
        cmd_network_suspicious
        ;;
    network-external)
        cmd_network_external
        ;;
    files)
        cmd_files
        ;;
    timeline)
        if [ $# -eq 0 ]; then
            echo "Error: timeline requires username argument"
            echo "Usage: $0 timeline <username>"
            exit 1
        fi
        cmd_timeline "$1"
        ;;
    search)
        if [ $# -eq 0 ]; then
            echo "Error: search requires pattern argument"
            echo "Usage: $0 search <pattern>"
            exit 1
        fi
        cmd_search "$1"
        ;;
    top-talkers)
        cmd_top_talkers
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Error: Unknown command: $COMMAND"
        echo
        show_help
        exit 1
        ;;
esac
