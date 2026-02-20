#!/bin/bash
# LinMon Installation Script with Security Hardening

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Detect nobody group (Debian/Ubuntu use 'nogroup', RHEL/Rocky use 'nobody')
if getent group nogroup >/dev/null 2>&1; then
    NOBODY_GROUP="nogroup"
else
    NOBODY_GROUP="nobody"
fi

echo -e "${GREEN}=== LinMon Installation ===${NC}"

# 1. Create dedicated system user
echo -e "${YELLOW}[1/8]${NC} Creating linmon system user..."
if id -u linmon >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} User 'linmon' already exists"
else
    useradd --system --no-create-home --shell /usr/sbin/nologin linmon
    echo -e "${GREEN}✓${NC} Created system user 'linmon'"
fi

# Check if we need to migrate from nobody to linmon
DAEMON_WAS_RUNNING=false
if systemctl is-active --quiet linmond 2>/dev/null; then
    DAEMON_WAS_RUNNING=true
    echo -e "${YELLOW}[Migration]${NC} Stopping daemon for ownership migration..."
    systemctl stop linmond
fi

# 2. Create log directory with proper permissions
echo -e "${YELLOW}[2/8]${NC} Creating log directory..."
mkdir -p /var/log/linmon
chown -R linmon:linmon /var/log/linmon
chmod 0750 /var/log/linmon

# Fix SELinux context for log directory (RHEL/Rocky/Fedora)
if command -v restorecon >/dev/null 2>&1 && [ -f /etc/selinux/config ]; then
    if sestatus 2>/dev/null | grep -q "SELinux status:.*enabled"; then
        restorecon -Rv /var/log/linmon
    fi
fi

echo -e "${GREEN}✓${NC} Log directory: /var/log/linmon (owner: linmon:linmon, mode: 0750)"

# 3. Create cache directory for package verification
echo -e "${YELLOW}[3/8]${NC} Creating cache directory..."
mkdir -p /var/cache/linmon
chown -R linmon:linmon /var/cache/linmon
chmod 0750 /var/cache/linmon

# Fix SELinux context for cache directory (RHEL/Rocky/Fedora)
if command -v restorecon >/dev/null 2>&1 && [ -f /etc/selinux/config ]; then
    if sestatus 2>/dev/null | grep -q "SELinux status:.*enabled"; then
        restorecon -Rv /var/cache/linmon
    fi
fi

echo -e "${GREEN}✓${NC} Cache directory: /var/cache/linmon (owner: linmon:linmon, mode: 0750)"

# 4. Create and secure config directory
echo -e "${YELLOW}[4/8]${NC} Installing configuration..."
mkdir -p /etc/linmon

# Remove immutable flag from existing files (from previous install)
chattr -i /etc/linmon/linmon.conf 2>/dev/null || true
chattr -i /usr/local/sbin/linmond 2>/dev/null || true

# Only copy config if it doesn't exist (don't overwrite existing config)
if [ ! -f /etc/linmon/linmon.conf ]; then
    cp linmon.conf /etc/linmon/
    echo -e "${GREEN}✓${NC} Installed default config to /etc/linmon/linmon.conf"
else
    echo -e "${YELLOW}⚠${NC} Config exists, not overwriting: /etc/linmon/linmon.conf"
fi

chown root:root /etc/linmon/linmon.conf
chmod 0600 /etc/linmon/linmon.conf

# Set immutable flag on config (requires root, prevents modification even by root)
chattr +i /etc/linmon/linmon.conf 2>/dev/null || echo -e "${YELLOW}⚠${NC} Could not set immutable flag (chattr not available or not supported)"

echo -e "${GREEN}✓${NC} Config permissions: root:root, mode: 0600"

# 5. Install binary
echo -e "${YELLOW}[5/8]${NC} Installing binary..."
if [ ! -f build/linmond ]; then
    echo -e "${RED}Error: build/linmond not found. Run 'make' first.${NC}"
    exit 1
fi

cp build/linmond /usr/local/sbin/
chown root:root /usr/local/sbin/linmond
chmod 0755 /usr/local/sbin/linmond

# Fix SELinux context if SELinux is enabled (RHEL/Rocky/Fedora)
if command -v restorecon >/dev/null 2>&1 && [ -f /etc/selinux/config ]; then
    if sestatus 2>/dev/null | grep -q "SELinux status:.*enabled"; then
        echo -e "${YELLOW}[SELinux]${NC} Restoring SELinux context..."
        restorecon -v /usr/local/sbin/linmond
        echo -e "${GREEN}✓${NC} SELinux context restored"
    fi
fi

# Set immutable flag on binary (requires root, prevents modification even by root)
chattr +i /usr/local/sbin/linmond 2>/dev/null || echo -e "${YELLOW}⚠${NC} Could not set immutable flag (chattr not available or not supported)"

echo -e "${GREEN}✓${NC} Installed binary: /usr/local/sbin/linmond"

# 6. Install systemd service
echo -e "${YELLOW}[6/8]${NC} Installing systemd service..."
if [ -f linmond.service ]; then
    cp linmond.service /etc/systemd/system/
    systemctl daemon-reload
    echo -e "${GREEN}✓${NC} Installed systemd service"
else
    echo -e "${YELLOW}⚠${NC} linmond.service not found, skipping systemd installation"
fi

# 7. Install logrotate config
echo -e "${YELLOW}[7/8]${NC} Installing logrotate configuration..."
if [ -f linmond.logrotate ]; then
    # Use linmon user instead of nobody
    sed "s/nobody nogroup/linmon linmon/" linmond.logrotate > /etc/logrotate.d/linmond
    chmod 0644 /etc/logrotate.d/linmond
    echo -e "${GREEN}✓${NC} Installed logrotate config to /etc/logrotate.d/linmond"
else
    echo -e "${YELLOW}⚠${NC} linmond.logrotate not found, skipping logrotate installation"
fi

# 8. Verify security
echo -e "${YELLOW}[8/8]${NC} Verifying security configuration..."

# Check config file permissions
CONF_PERM=$(stat -c %a /etc/linmon/linmon.conf)
if [ "$CONF_PERM" != "600" ]; then
    echo -e "${RED}✗${NC} Config permissions incorrect: $CONF_PERM (expected 600)"
else
    echo -e "${GREEN}✓${NC} Config permissions correct"
fi

# Check config file owner
CONF_OWNER=$(stat -c %U:%G /etc/linmon/linmon.conf)
if [ "$CONF_OWNER" != "root:root" ]; then
    echo -e "${RED}✗${NC} Config owner incorrect: $CONF_OWNER (expected root:root)"
else
    echo -e "${GREEN}✓${NC} Config owner correct"
fi

# Check binary capabilities (should have none)
CAPS=$(getcap /usr/local/sbin/linmond 2>/dev/null || echo "none")
if [ "$CAPS" != "none" ] && [ "$CAPS" != "" ]; then
    echo -e "${YELLOW}⚠${NC} Binary has capabilities: $CAPS"
else
    echo -e "${GREEN}✓${NC} Binary has no capabilities (will run as root initially)"
fi

# 9. Restart daemon if it was running (after migration)
if [ "$DAEMON_WAS_RUNNING" = true ]; then
    echo -e "${YELLOW}[Migration]${NC} Restarting daemon after ownership migration..."
    systemctl start linmond
    sleep 2
    if systemctl is-active --quiet linmond; then
        echo -e "${GREEN}✓${NC} Daemon successfully restarted"
    else
        echo -e "${RED}✗${NC} Daemon failed to restart - check: systemctl status linmond"
    fi
fi

# 10. Enable and start service (if not already running)
if systemctl list-unit-files | grep -q linmond.service && [ "$DAEMON_WAS_RUNNING" = false ]; then
    read -p "Enable and start linmond service now? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        systemctl enable linmond
        systemctl restart linmond
        sleep 2

        # Show service status
        echo -e "\n${GREEN}=== Service Status ===${NC}"
        systemctl status linmond --no-pager || true

        # Show privilege drop in logs
        echo -e "\n${GREEN}=== Security Verification ===${NC}"
        journalctl -u linmond -n 30 --no-pager | grep -E "(Dropped|capabilities|UID/GID)" || \
            echo -e "${YELLOW}⚠${NC} Could not find privilege drop messages in logs"
    else
        echo -e "${YELLOW}⚠${NC} Service not started. Start manually with: systemctl start linmond"
    fi
fi

# Verify logrotate (no step number, part of final checks)
echo -e "\n${YELLOW}Verifying logrotate configuration...${NC}"
if [ -f /etc/logrotate.d/linmond ]; then
    # Test logrotate config syntax
    if logrotate -d /etc/logrotate.d/linmond >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Logrotate config is valid"
    else
        echo -e "${YELLOW}⚠${NC} Logrotate config may have syntax errors"
    fi
else
    echo -e "${YELLOW}⚠${NC} Logrotate config not found"
fi

echo -e "\n${GREEN}=== Installation Complete ===${NC}"
echo -e "Binary:    /usr/local/sbin/linmond"
echo -e "Config:    /etc/linmon/linmon.conf"
echo -e "Logs:      /var/log/linmon/events.json (owner: linmon:linmon)"
echo -e "Cache:     /var/cache/linmon (owner: linmon:linmon)"
echo -e "Logrotate: /etc/logrotate.d/linmond"
echo -e "Service:   systemctl status linmond"
echo -e "\n${GREEN}Security features enabled:${NC}"
echo -e "  ✓ Dedicated system user (linmon)"
echo -e "  ✓ Capability dropping (all capabilities cleared)"
echo -e "  ✓ UID/GID dropping (runs as linmon:linmon)"
echo -e "  ✓ Config file validation (permissions checked)"
echo -e "  ✓ Path traversal protection (log_file validated)"
echo -e "  ✓ Systemd hardening (if service installed)"
echo -e "\n${YELLOW}See SECURITY.md for detailed security documentation${NC}"
