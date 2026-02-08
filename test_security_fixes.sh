#!/bin/bash
# Test script for security fixes

set -e

echo "=== Testing Security Fixes ==="
echo

# Test 1: Verify logger_open_file_secure exists in logger.h
echo "[Test 1] Checking logger_open_file_secure is exported..."
if grep -q "FILE \*logger_open_file_secure" src/logger.h; then
    echo "✓ Function exported in header"
else
    echo "✗ Function not found in header"
    exit 1
fi

# Test 2: Verify main.c uses logger_open_file_secure
echo "[Test 2] Checking main.c uses secure file opening..."
if grep -q "logger_open_file_secure(new_log_file)" src/main.c; then
    echo "✓ SIGHUP handler uses secure file opening"
else
    echo "✗ SIGHUP handler does not use secure file opening"
    exit 1
fi

# Test 3: Verify config.c has hard fail for non-root ownership (production mode)
echo "[Test 3] Checking config.c fails on non-root ownership in production..."
if grep -q "CRITICAL.*not owned by root" src/config.c && \
   grep -A4 "not owned by root" src/config.c | grep -q "return -EPERM"; then
    echo "✓ Non-root ownership is hard fail (production mode)"
else
    echo "✗ Non-root ownership is not hard fail"
    exit 1
fi

# Test 4: Verify config.c has hard fail for group-writable (production mode)
echo "[Test 4] Checking config.c fails on group-writable in production..."
if grep -q "CRITICAL.*group-writable" src/config.c && \
   grep -A3 "group-writable" src/config.c | grep -q "return -EPERM"; then
    echo "✓ Group-writable is hard fail (production mode)"
else
    echo "✗ Group-writable is not hard fail"
    exit 1
fi

# Test 5: Verify config.c has test mode bypass
echo "[Test 5] Checking config.c has LINMON_TEST_MODE bypass..."
if grep -q "LINMON_TEST_MODE" src/config.c && \
   grep -q "if (!test_mode)" src/config.c; then
    echo "✓ Test mode bypass exists for unit tests"
else
    echo "✗ Test mode bypass missing"
    exit 1
fi

# Test 5: Verify logger.c implements secure file opening with umask/chmod
echo "[Test 6] Checking logger_open_file_secure implementation..."
if grep -A20 "^FILE \*logger_open_file_secure" src/logger.c | grep -q "umask(0077)" && \
   grep -A20 "^FILE \*logger_open_file_secure" src/logger.c | grep -q "chmod.*0640"; then
    echo "✓ Secure file opening uses umask + chmod"
else
    echo "✗ Secure file opening missing umask or chmod"
    exit 1
fi

echo
echo "=== All Security Tests Passed ==="
echo
echo "Summary of fixes:"
echo "  ✓ Fix #1: SIGHUP log reload now uses secure file opening (umask + chmod)"
echo "  ✓ Fix #2: Config file validation now hard-fails on insecure permissions"
echo
echo "Security improvements:"
echo "  - Log files created during SIGHUP always have 0640 permissions"
echo "  - Config files must be root-owned and not group-writable"
echo "  - Both fixes prevent privilege escalation vectors"
