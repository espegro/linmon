#!/bin/bash
# Setup LinMon failure alerting via systemd OnFailure
#
# Usage: sudo ./scripts/setup-failure-alerting.sh

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_ok() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root"
    exit 1
fi

echo "╔═══════════════════════════════════════════════════════╗"
echo "║     LinMon Failure Alerting Setup                     ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# 1. Install failure alert script
echo "[1/4] Installing failure alert script..."

ALERT_SCRIPT="/usr/local/sbin/linmon-failure-alert.sh"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -f "$SCRIPT_DIR/linmon-failure-alert.sh" ]; then
    cp "$SCRIPT_DIR/linmon-failure-alert.sh" "$ALERT_SCRIPT"
    chmod +x "$ALERT_SCRIPT"
    print_ok "Alert script installed to $ALERT_SCRIPT"
else
    print_error "Alert script not found in $SCRIPT_DIR"
    exit 1
fi

echo ""

# 2. Create systemd alert service
echo "[2/4] Creating systemd alert service..."

cat > /etc/systemd/system/linmon-failure-alert.service <<'EOF'
[Unit]
Description=LinMon Failure Alert Handler
Documentation=https://github.com/your-org/linmon

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/linmon-failure-alert.sh
StandardOutput=journal
StandardError=journal

# Run as root to access logs and send alerts
User=root
EOF

print_ok "Created /etc/systemd/system/linmon-failure-alert.service"
echo ""

# 3. Update LinMon service to trigger alert on failure
echo "[3/4] Configuring LinMon to trigger alerts on failure..."

if [ ! -f /etc/systemd/system/linmond.service ]; then
    print_error "LinMon systemd service not found"
    echo "      Install LinMon first: sudo make install"
    exit 1
fi

# Create override directory
mkdir -p /etc/systemd/system/linmond.service.d

# Create override configuration
cat > /etc/systemd/system/linmond.service.d/failure-alert.conf <<'EOF'
[Unit]
# Trigger alert service when LinMon fails
OnFailure=linmon-failure-alert.service

[Service]
# Allow 3 restart attempts before giving up
StartLimitBurst=3
StartLimitIntervalSec=60
EOF

print_ok "Created failure alerting override"
echo ""

# 4. Reload systemd and verify
echo "[4/4] Reloading systemd configuration..."

systemctl daemon-reload
print_ok "Systemd configuration reloaded"

# Verify configuration
if systemctl show linmond | grep -q "OnFailure=linmon-failure-alert.service"; then
    print_ok "LinMon OnFailure configured correctly"
else
    print_warn "Could not verify OnFailure configuration"
fi

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║              Configuration Complete                   ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "Failure alerting is now active!"
echo ""
echo "How it works:"
echo "  1. If LinMon fails to start → linmon-failure-alert.service runs"
echo "  2. Alert script checks for BPF load failures"
echo "  3. Logs CRITICAL alerts to syslog/journal"
echo "  4. Creates /var/log/linmon/CRITICAL_BPF_LOAD_FAILED if BPF blocked"
echo "  5. Checks for rootkit indicators (Singularity, hidden modules)"
echo ""
echo "Testing the alert system:"
echo "  sudo systemctl stop linmond"
echo "  sudo systemctl kill linmond --signal=KILL"
echo "  sudo journalctl -u linmon-failure-alert --since '1 minute ago'"
echo ""
echo "Optional: Configure email alerts"
echo "  export MAILTO=admin@example.com"
echo "  echo 'MAILTO=admin@example.com' >> /etc/environment"
echo ""
echo "Monitor for alerts:"
echo "  sudo journalctl -f -u linmond -u linmon-failure-alert"
echo ""
