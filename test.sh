#!/bin/bash
# Quick test script for LinMon

set -e

echo "==> Building LinMon..."
make clean
make

echo ""
echo "==> Creating log directory..."
sudo mkdir -p /var/log/linmon
sudo chown $(whoami):$(whoami) /var/log/linmon

echo ""
echo "==> LinMon built successfully!"
echo ""
echo "To run LinMon (requires sudo):"
echo "  sudo ./build/linmond"
echo ""
echo "In another terminal, generate some activity:"
echo "  ls -la"
echo "  ps aux | head"
echo "  cat /etc/hostname"
echo ""
echo "Then check the logs:"
echo "  tail -f /var/log/linmon/events.json"
echo ""
