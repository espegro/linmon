#!/bin/bash
# LinMon Failure Alert Script
# Called by systemd OnFailure when LinMon fails to start
#
# This script checks for BPF load failures and alerts administrators
# Helps detect rootkit interference (e.g., Singularity blocking bpf() syscall)

ALERT_FILE="/var/log/linmon/CRITICAL_BPF_LOAD_FAILED"
LOG_DIR="/var/log/linmon"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Check if this is a BPF load failure
if [ -f "$ALERT_FILE" ]; then
    ALERT_MSG="CRITICAL: LinMon failed to load BPF programs - possible rootkit interference!"

    # Log to syslog with high priority
    logger -t linmon-alert -p daemon.crit "$ALERT_MSG"
    logger -t linmon-alert -p daemon.crit "Alert details in: $ALERT_FILE"

    # Check for known rootkit indicators in dmesg
    ROOTKIT_INDICATORS=$(dmesg | grep -iE "(singularity|rootkit|bpf.*denied|bpf.*blocked|module.*blocked)" | tail -10)
    if [ -n "$ROOTKIT_INDICATORS" ]; then
        logger -t linmon-alert -p daemon.crit "Rootkit indicators found in dmesg:"
        echo "$ROOTKIT_INDICATORS" | while read -r line; do
            logger -t linmon-alert -p daemon.crit "  $line"
        done
    fi

    # Check LKRG logs
    LKRG_LOGS=$(dmesg | grep LKRG | tail -10)
    if [ -n "$LKRG_LOGS" ]; then
        logger -t linmon-alert -p daemon.warning "Recent LKRG activity:"
        echo "$LKRG_LOGS" | while read -r line; do
            logger -t linmon-alert -p daemon.warning "  $line"
        done
    fi

    # Check for hidden modules (LKRG detection)
    if [ -f /sys/kernel/lkrg/hidden_module ]; then
        logger -t linmon-alert -p daemon.crit "LKRG reports hidden module detected!"
    fi

    # Send email if configured
    if command -v mail &>/dev/null && [ -n "$MAILTO" ]; then
        {
            echo "$ALERT_MSG"
            echo ""
            echo "Details from $ALERT_FILE:"
            cat "$ALERT_FILE"
            echo ""
            echo "Recent dmesg:"
            dmesg | tail -50
            echo ""
            echo "LKRG status:"
            lsmod | grep lkrg || echo "LKRG not loaded"
            [ -f /sys/kernel/lkrg/block_modules ] && cat /sys/kernel/lkrg/block_modules || echo "N/A"
        } | mail -s "SECURITY ALERT: LinMon BPF Loading Failed on $(hostname)" "$MAILTO"
    fi

    # Create a persistent alert marker for monitoring systems
    touch "$LOG_DIR/SECURITY_ALERT_ACTIVE"
    echo "$(date): BPF load failure - possible rootkit" >> "$LOG_DIR/SECURITY_ALERT_ACTIVE"

else
    # Generic LinMon failure (not BPF-specific)
    logger -t linmon-alert -p daemon.err "LinMon daemon failed (reason unknown)"

    # Check systemd journal for details
    JOURNAL_ERRORS=$(journalctl -u linmond --since "5 minutes ago" --no-pager | tail -20)
    if [ -n "$JOURNAL_ERRORS" ]; then
        logger -t linmon-alert -p daemon.err "Recent LinMon errors:"
        echo "$JOURNAL_ERRORS" | while read -r line; do
            logger -t linmon-alert -p daemon.err "  $line"
        done
    fi
fi

# Check how many times LinMon has failed recently
FAILURE_COUNT=$(systemctl show linmond -p NRestarts --value)
if [ "$FAILURE_COUNT" -ge 3 ]; then
    logger -t linmon-alert -p daemon.crit "LinMon has failed $FAILURE_COUNT times - possible persistent attack"
fi

# Exit with error to signal systemd
exit 1
