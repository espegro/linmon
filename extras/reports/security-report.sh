#!/bin/bash
# LinMon Security Report - Security events and anomalies
# Usage: ./security-report.sh [hours] [log_dir]
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
MAGENTA='\033[0;35m'
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

echo -e "${RED}═══════════════════════════════════════════════════════${NC}"
echo -e "${RED}    LinMon Security Report - Last ${HOURS} Hours${NC}"
echo -e "${RED}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "Report generated: $(date)"
echo "Time range: ${CUTOFF_TIME}Z to $(date -u +"%Y-%m-%dT%H:%M:%S")Z"
echo ""

# Function to read all events (current + rotated logs)
read_all_events() {
    (cat "$EVENTS_JSON" 2>/dev/null || true
     for f in "${LOG_DIR}"/events.json.[0-9]*; do
         [ -f "$f" ] && cat "$f" || true
     done) | jq -c "select(.timestamp >= \"${CUTOFF_TIME}\")"
}

# MITRE ATT&CK Security Events
echo -e "${RED}════════════════════════════════════════════════════════${NC}"
echo -e "${RED}  MITRE ATT&CK Security Events${NC}"
echo -e "${RED}════════════════════════════════════════════════════════${NC}"
echo ""

# T1055 - Process Injection (ptrace)
PTRACE_COUNT=$(read_all_events | jq -r 'select(.type == "security_ptrace")' | wc -l)
if [ "$PTRACE_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠ T1055 - Process Injection Detected: ${PTRACE_COUNT} events${NC}"
    echo "────────────────────────────────────────────────────────"
    read_all_events | jq -r 'select(.type == "security_ptrace") |
        "  [\(.timestamp | split("T")[1] | split(".")[0])] User: \(.username // "unknown") PID: \(.pid) → Target PID: \(.target_pid) Process: \(.process_name // .comm)"' | head -10
    [ "$PTRACE_COUNT" -gt 10 ] && echo "  ... and $((PTRACE_COUNT - 10)) more"
    echo ""
fi

# T1547.006 - Kernel Module Loading
MODULE_COUNT=$(read_all_events | jq -r 'select(.type == "security_module_load")' | wc -l)
if [ "$MODULE_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠ T1547.006 - Kernel Module Loading: ${MODULE_COUNT} events${NC}"
    echo "────────────────────────────────────────────────────────"
    read_all_events | jq -r 'select(.type == "security_module_load") |
        "  [\(.timestamp | split("T")[1] | split(".")[0])] User: \(.username // "unknown") Process: \(.process_name // .comm)"' | head -10
    [ "$MODULE_COUNT" -gt 10 ] && echo "  ... and $((MODULE_COUNT - 10)) more"
    echo ""
fi

# T1620 - Fileless Malware (memfd_create)
MEMFD_COUNT=$(read_all_events | jq -r 'select(.type == "security_memfd_create")' | wc -l)
if [ "$MEMFD_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠ T1620 - Fileless Malware (memfd): ${MEMFD_COUNT} events${NC}"
    echo "────────────────────────────────────────────────────────"
    read_all_events | jq -r 'select(.type == "security_memfd_create") |
        "  [\(.timestamp | split("T")[1] | split(".")[0])] User: \(.username // "unknown") Process: \(.process_name // .comm) Name: \(.memfd_name // "N/A")"' | head -10
    [ "$MEMFD_COUNT" -gt 10 ] && echo "  ... and $((MEMFD_COUNT - 10)) more"
    echo ""
fi

# T1571 - Bind Shell / C2 Server
BIND_COUNT=$(read_all_events | jq -r 'select(.type == "security_bind")' | wc -l)
if [ "$BIND_COUNT" -gt 0 ]; then
    echo -e "${RED}🔴 T1571 - Bind Shell / C2 Server: ${BIND_COUNT} events${NC}"
    echo "────────────────────────────────────────────────────────"
    read_all_events | jq -r 'select(.type == "security_bind") |
        "  [\(.timestamp | split("T")[1] | split(".")[0])] User: \(.username // "unknown") Process: \(.process_name // .comm) Port: \(.port)"' | head -10
    [ "$BIND_COUNT" -gt 10 ] && echo "  ... and $((BIND_COUNT - 10)) more"
    echo ""
fi

# T1611 - Container Escape (unshare)
UNSHARE_COUNT=$(read_all_events | jq -r 'select(.type == "security_unshare")' | wc -l)
if [ "$UNSHARE_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠ T1611 - Container Escape (unshare): ${UNSHARE_COUNT} events${NC}"
    echo "────────────────────────────────────────────────────────"
    read_all_events | jq -r 'select(.type == "security_unshare") |
        "  [\(.timestamp | split("T")[1] | split(".")[0])] User: \(.username // "unknown") Process: \(.process_name // .comm)"' | head -10
    [ "$UNSHARE_COUNT" -gt 10 ] && echo "  ... and $((UNSHARE_COUNT - 10)) more"
    echo ""
fi

# T1620 - Fileless Execution (execveat)
EXECVEAT_COUNT=$(read_all_events | jq -r 'select(.type == "security_execveat")' | wc -l)
if [ "$EXECVEAT_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠ T1620 - Fileless Execution (execveat): ${EXECVEAT_COUNT} events${NC}"
    echo "────────────────────────────────────────────────────────"
    read_all_events | jq -r 'select(.type == "security_execveat") |
        "  [\(.timestamp | split("T")[1] | split(".")[0])] User: \(.username // "unknown") Process: \(.process_name // .comm)"' | head -10
    [ "$EXECVEAT_COUNT" -gt 10 ] && echo "  ... and $((EXECVEAT_COUNT - 10)) more"
    echo ""
fi

# T1014 - eBPF Rootkit
BPF_COUNT=$(read_all_events | jq -r 'select(.type == "security_bpf")' | wc -l)
if [ "$BPF_COUNT" -gt 0 ]; then
    echo -e "${RED}🔴 T1014 - eBPF Rootkit: ${BPF_COUNT} events${NC}"
    echo "────────────────────────────────────────────────────────"
    read_all_events | jq -r 'select(.type == "security_bpf") |
        "  [\(.timestamp | split("T")[1] | split(".")[0])] User: \(.username // "unknown") Process: \(.process_name // .comm) BPF cmd: \(.bpf_cmd // "N/A")"' | head -10
    [ "$BPF_COUNT" -gt 10 ] && echo "  ... and $((BPF_COUNT - 10)) more"
    echo ""
fi

# T1003.008 - Credential File Access
CRED_COUNT=$(read_all_events | jq -r 'select(.type == "security_cred_read")' | wc -l)
if [ "$CRED_COUNT" -gt 0 ]; then
    echo -e "${RED}🔴 T1003.008 - Credential File Access: ${CRED_COUNT} events${NC}"
    echo "────────────────────────────────────────────────────────"
    read_all_events | jq -r 'select(.type == "security_cred_read") |
        "  [\(.timestamp | split("T")[1] | split(".")[0])] User: \(.username // "unknown") Process: \(.process_name // .comm) File: \(.cred_file // "N/A") Path: \(.path // "N/A")"' | head -10
    [ "$CRED_COUNT" -gt 10 ] && echo "  ... and $((CRED_COUNT - 10)) more"
    echo ""
fi

# T1574.006 - LD_PRELOAD Hijacking
LDPRELOAD_COUNT=$(read_all_events | jq -r 'select(.type == "security_ldpreload")' | wc -l)
if [ "$LDPRELOAD_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠ T1574.006 - LD_PRELOAD Hijacking: ${LDPRELOAD_COUNT} events${NC}"
    echo "────────────────────────────────────────────────────────"
    read_all_events | jq -r 'select(.type == "security_ldpreload") |
        "  [\(.timestamp | split("T")[1] | split(".")[0])] User: \(.username // "unknown") Process: \(.process_name // .comm) Path: \(.path // "N/A")"' | head -10
    [ "$LDPRELOAD_COUNT" -gt 10 ] && echo "  ... and $((LDPRELOAD_COUNT - 10)) more"
    echo ""
fi

# Privilege Escalation Analysis
echo -e "${RED}════════════════════════════════════════════════════════${NC}"
echo -e "${RED}  Privilege Escalation Analysis${NC}"
echo -e "${RED}════════════════════════════════════════════════════════${NC}"
echo ""

# Sudo usage by user
echo -e "${YELLOW}Sudo Usage by User:${NC}"
echo "────────────────────────────────────────────────────────"
read_all_events | jq -r 'select(.type == "priv_sudo") | .old_uid' | sort | uniq -c | sort -rn | awk '{printf "  UID %-10s %8d sudo calls\n", $2, $1}'
echo ""

# Root logins (UID 0 process_exec events)
ROOT_LOGINS=$(read_all_events | jq -r 'select(.type == "process_exec" and .uid == 0 and .comm == "bash")' | wc -l)
if [ "$ROOT_LOGINS" -gt 0 ]; then
    echo -e "${YELLOW}Root Shell Sessions: ${ROOT_LOGINS}${NC}"
    echo "────────────────────────────────────────────────────────"
    read_all_events | jq -r 'select(.type == "process_exec" and .uid == 0 and .comm == "bash") |
        "  [\(.timestamp | split("T")[1] | split(".")[0])] TTY: \(.tty // "none") Process: \(.process_name // .comm)"' | head -10
    [ "$ROOT_LOGINS" -gt 10 ] && echo "  ... and $((ROOT_LOGINS - 10)) more"
    echo ""
fi

# Network Security Analysis
echo -e "${RED}════════════════════════════════════════════════════════${NC}"
echo -e "${RED}  Network Security Analysis${NC}"
echo -e "${RED}════════════════════════════════════════════════════════${NC}"
echo ""

# Suspicious ports (common C2/backdoor ports)
echo -e "${YELLOW}Connections to Suspicious Ports:${NC}"
echo "────────────────────────────────────────────────────────"
SUSPICIOUS_PORTS="4444 5555 6666 7777 8888 9999 31337 12345"
for port in $SUSPICIOUS_PORTS; do
    PORT_COUNT=$(read_all_events | jq -r "select(.type == \"net_connect_tcp\" and .dport == $port)" | wc -l)
    if [ "$PORT_COUNT" -gt 0 ]; then
        echo -e "  ${RED}Port $port: $PORT_COUNT connections${NC}"
        read_all_events | jq -r "select(.type == \"net_connect_tcp\" and .dport == $port) |
            \"    [\(.timestamp | split(\"T\")[1] | split(\".\")[0])] \(.process_name // .comm) → \(.daddr):\(.dport)\"" | head -5
    fi
done
echo ""

# Outbound connections to non-standard ports (not 80, 443, 22, 53)
NONSTANDARD_COUNT=$(read_all_events | jq -r 'select(.type == "net_connect_tcp" and (.dport != 80 and .dport != 443 and .dport != 22 and .dport != 53))' | wc -l)
if [ "$NONSTANDARD_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}Non-Standard Port Connections: ${NONSTANDARD_COUNT} total${NC}"
    echo "────────────────────────────────────────────────────────"
    echo "Top 10 non-standard destination ports:"
    read_all_events | jq -r 'select(.type == "net_connect_tcp" and (.dport != 80 and .dport != 443 and .dport != 22 and .dport != 53)) | .dport' | sort | uniq -c | sort -rn | head -10 | awk '{printf "  Port %-10s %8d connections\n", $2, $1}'
    echo ""
fi

# Tamper Detection
echo -e "${RED}════════════════════════════════════════════════════════${NC}"
echo -e "${RED}  Tamper Detection & Integrity${NC}"
echo -e "${RED}════════════════════════════════════════════════════════${NC}"
echo ""

# Smart sequence gap detection - ignore daemon restarts, only flag tampering
DAEMON_START=$(read_all_events | jq -r 'select(.type == "daemon_start")' | wc -l)
DAEMON_RELOAD=$(read_all_events | jq -r 'select(.type == "daemon_reload")' | wc -l)
DAEMON_SHUTDOWN=$(read_all_events | jq -r 'select(.type == "daemon_shutdown")' | wc -l)

# Check for suspicious gaps (small gaps within sessions, not large jumps from restarts)
SUSPICIOUS_GAPS=$(read_all_events | jq -r 'select(.seq) | .seq' | sort -n | awk '
    NR > 1 && $1 != prev + 1 {
        gap_size = $1 - prev - 1
        # Only report gaps < 100 (likely tampering, not daemon restart)
        if (gap_size < 100 && gap_size > 0) {
            suspicious++
            print "  Seq " prev+1 " to " ($1-1) " (" gap_size " events missing)"
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
    echo -e "${RED}🔴 CRITICAL: Suspicious sequence gaps detected!${NC}"
    echo "────────────────────────────────────────────────────────"
    echo "$SUSPICIOUS_GAPS" | grep "^  Seq"
    echo "  This strongly suggests deleted events (log tampering)."
    if [ "$DAEMON_START" -gt 1 ]; then
        echo "  Note: $DAEMON_START daemon restarts detected (their sequence resets were ignored)."
    fi
    echo ""
elif [ "$DAEMON_START" -gt 1 ]; then
    echo -e "${GREEN}✓ No suspicious gaps detected${NC}"
    echo "  $DAEMON_START daemon restarts in time range (sequence resets are normal)."
    echo ""
else
    echo -e "${GREEN}✓ No sequence gaps detected - log integrity OK${NC}"
    echo ""
fi

echo -e "${YELLOW}Daemon Lifecycle Events:${NC}"
echo "────────────────────────────────────────────────────────"
echo "  Daemon starts:    ${DAEMON_START}"
echo "  Config reloads:   ${DAEMON_RELOAD}"
echo "  Daemon shutdowns: ${DAEMON_SHUTDOWN}"

if [ "$DAEMON_SHUTDOWN" -gt 0 ]; then
    echo ""
    echo "  Recent shutdowns:"
    read_all_events | jq -r 'select(.type == "daemon_shutdown") |
        "    [\(.timestamp | split("T")[1] | split(".")[0])] Signal: \(.signal // "N/A") Sender PID: \(.sender_pid // "N/A") UID: \(.sender_uid // "N/A")"'
fi
echo ""

# Summary
echo -e "${RED}════════════════════════════════════════════════════════${NC}"
echo -e "${RED}  Security Summary${NC}"
echo -e "${RED}════════════════════════════════════════════════════════${NC}"
echo ""

TOTAL_SECURITY=$(read_all_events | jq -r 'select(.type | startswith("security_"))' | wc -l)
if [ "$TOTAL_SECURITY" -eq 0 ]; then
    echo -e "${GREEN}✓ No security events detected in last ${HOURS} hours${NC}"
    echo -e "${GREEN}  System appears normal.${NC}"
else
    echo -e "${YELLOW}⚠ ${TOTAL_SECURITY} security events detected${NC}"
    echo -e "${YELLOW}  Review events above for potential threats.${NC}"
fi

echo ""
echo "Report complete. Review all events marked with 🔴 for immediate action."
echo ""
