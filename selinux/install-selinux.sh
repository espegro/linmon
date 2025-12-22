#!/bin/bash
# Install LinMon SELinux policy module for RHEL 9 / Rocky Linux 9 / AlmaLinux 9
#
# This script compiles and installs the SELinux policy module that allows
# linmond to use eBPF for system monitoring.
#
# Usage: sudo ./install-selinux.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Check if SELinux is enabled
if ! command -v getenforce &> /dev/null; then
    echo "SELinux tools not found. Skipping SELinux policy installation."
    exit 0
fi

SELINUX_MODE=$(getenforce)
if [ "$SELINUX_MODE" = "Disabled" ]; then
    echo "SELinux is disabled. No policy installation needed."
    exit 0
fi

echo "SELinux is $SELINUX_MODE"
echo "Installing LinMon SELinux policy module..."

# Check for required tools
if ! command -v checkmodule &> /dev/null; then
    echo "Installing SELinux policy development tools..."
    dnf install -y policycoreutils-devel selinux-policy-devel || \
    yum install -y policycoreutils-devel selinux-policy-devel || \
    apt-get install -y policycoreutils selinux-policy-dev
fi

# Compile the policy module
echo "Compiling policy module..."
checkmodule -M -m -o linmond.mod linmond.te

# Create the policy package
echo "Creating policy package..."
semodule_package -o linmond.pp -m linmond.mod

# Install the policy module
echo "Installing policy module..."
semodule -i linmond.pp

# Verify installation
echo ""
echo "Verifying installation..."
if semodule -l | grep -q linmond; then
    echo "SUCCESS: LinMon SELinux policy module installed"
    semodule -l | grep linmond
else
    echo "WARNING: Policy module may not have installed correctly"
    exit 1
fi

echo ""
echo "You can now start linmond with: systemctl start linmond"
echo ""
echo "If you still see SELinux denials, check with:"
echo "  ausearch -m avc -ts recent | grep linmond"
echo ""
echo "To generate additional policy from denials:"
echo "  ausearch -m avc -ts recent | audit2allow -M linmond_extra"
echo "  semodule -i linmond_extra.pp"
