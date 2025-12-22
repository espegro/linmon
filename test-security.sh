#!/bin/bash
# test-security.sh - Integration tests for security monitoring features
# Tests MITRE ATT&CK detection: T1055, T1547.006, T1620, T1571, T1611, T1014

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOGFILE="/var/log/linmon/events.json"
PASSED=0
FAILED=0
SKIPPED=0

echo "=== LinMon Security Monitoring Tests ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Tests must be run as root${NC}"
    exit 1
fi

# Check if linmond is running
if ! pgrep -x linmond > /dev/null; then
    echo -e "${YELLOW}Warning: linmond is not running${NC}"
    echo "Start linmond first with security monitoring enabled in /etc/linmon/linmon.conf:"
    echo "  monitor_ptrace = true    # T1055 Process Injection"
    echo "  monitor_modules = true   # T1547.006 Kernel Modules"
    echo "  monitor_memfd = true     # T1620 Fileless Malware"
    echo "  monitor_bind = true      # T1571 Bind Shell / C2"
    echo "  monitor_unshare = true   # T1611 Container Escape"
    echo "  monitor_execveat = true  # T1620 Fileless Execution"
    echo "  monitor_bpf = true       # T1014 eBPF Rootkit"
    exit 1
fi

# Check if log file exists
if [ ! -f "$LOGFILE" ]; then
    echo -e "${RED}Error: Log file $LOGFILE not found${NC}"
    exit 1
fi

# Test 1: ptrace detection (T1055 - Process Injection)
test_ptrace() {
    echo -n "Testing ptrace detection (T1055)... "

    # Get current log position
    BEFORE=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)

    # Run strace on a simple command (uses PTRACE_ATTACH)
    timeout 2 strace -e trace=none /bin/true >/dev/null 2>&1 || true

    sleep 1

    # Check for ptrace event
    AFTER=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)
    NEW_LINES=$((AFTER - BEFORE))

    if [ $NEW_LINES -gt 0 ] && tail -n $NEW_LINES "$LOGFILE" | grep -q '"type":"security_ptrace"'; then
        echo -e "${GREEN}PASS${NC}"
        ((PASSED++))
        # Show the event
        tail -n $NEW_LINES "$LOGFILE" | grep '"type":"security_ptrace"' | head -1 | python3 -m json.tool 2>/dev/null || true
    else
        echo -e "${RED}FAIL${NC} (no ptrace event detected)"
        ((FAILED++))
    fi
}

# Test 2: memfd_create detection (T1620 - Fileless Malware)
test_memfd() {
    echo -n "Testing memfd_create detection (T1620)... "

    BEFORE=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)

    # Create a memfd using Python
    python3 -c "
import os
try:
    fd = os.memfd_create('linmon_test_memfd')
    os.close(fd)
except Exception as e:
    pass
" 2>/dev/null || true

    sleep 1

    AFTER=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)
    NEW_LINES=$((AFTER - BEFORE))

    if [ $NEW_LINES -gt 0 ] && tail -n $NEW_LINES "$LOGFILE" | grep -q '"type":"security_memfd_create"'; then
        echo -e "${GREEN}PASS${NC}"
        ((PASSED++))
        # Show the event
        tail -n $NEW_LINES "$LOGFILE" | grep '"type":"security_memfd_create"' | head -1 | python3 -m json.tool 2>/dev/null || true
    else
        echo -e "${RED}FAIL${NC} (no memfd event detected)"
        ((FAILED++))
    fi
}

# Test 3: Module loading detection (T1547.006)
# Note: We don't actually load a module (that would be dangerous)
# Instead we verify the BPF programs are attached
test_module_attachment() {
    echo -n "Testing module load monitoring attachment (T1547.006)... "

    # Check if the BPF programs are attached by looking at startup output
    if journalctl -u linmond --since "10 minutes ago" 2>/dev/null | grep -q "Module loading"; then
        echo -e "${GREEN}PASS${NC} (BPF program attached)"
        ((PASSED++))
    elif dmesg 2>/dev/null | grep -q "linmon.*module"; then
        echo -e "${GREEN}PASS${NC} (BPF program attached)"
        ((PASSED++))
    else
        # Just check that linmond is running - module monitoring is best-effort
        echo -e "${YELLOW}SKIP${NC} (cannot verify without loading module)"
        ((SKIPPED++))
    fi
}

# Test 4: bind() detection (T1571 - Bind Shell / C2)
test_bind() {
    echo -n "Testing bind() detection (T1571)... "

    BEFORE=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)

    # Create a simple Python server that binds to a port
    python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 59999))
    s.close()
except Exception as e:
    pass
" 2>/dev/null || true

    sleep 1

    AFTER=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)
    NEW_LINES=$((AFTER - BEFORE))

    if [ $NEW_LINES -gt 0 ] && tail -n $NEW_LINES "$LOGFILE" | grep -q '"type":"security_bind"'; then
        echo -e "${GREEN}PASS${NC}"
        ((PASSED++))
        # Show the event
        tail -n $NEW_LINES "$LOGFILE" | grep '"type":"security_bind"' | head -1 | python3 -m json.tool 2>/dev/null || true
    else
        echo -e "${RED}FAIL${NC} (no bind event detected)"
        ((FAILED++))
    fi
}

# Test 5: unshare() detection (T1611 - Container Escape)
test_unshare() {
    echo -n "Testing unshare() detection (T1611)... "

    BEFORE=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)

    # Create a new user namespace (safe, unprivileged operation)
    unshare --user true 2>/dev/null || true

    sleep 1

    AFTER=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)
    NEW_LINES=$((AFTER - BEFORE))

    if [ $NEW_LINES -gt 0 ] && tail -n $NEW_LINES "$LOGFILE" | grep -q '"type":"security_unshare"'; then
        echo -e "${GREEN}PASS${NC}"
        ((PASSED++))
        # Show the event
        tail -n $NEW_LINES "$LOGFILE" | grep '"type":"security_unshare"' | head -1 | python3 -m json.tool 2>/dev/null || true
    else
        echo -e "${RED}FAIL${NC} (no unshare event detected)"
        ((FAILED++))
    fi
}

# Test 6: execveat() detection (T1620 - Fileless Execution)
test_execveat() {
    echo -n "Testing execveat() detection (T1620)... "

    BEFORE=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)

    # Use Python to call execveat via fexecve (if available)
    python3 -c "
import os
try:
    # Open a simple executable
    fd = os.open('/bin/true', os.O_RDONLY)
    # fexecve uses execveat internally
    # We fork first to not replace our process
    pid = os.fork()
    if pid == 0:
        try:
            os.fexecve(fd, ['/bin/true'], os.environ)
        except:
            os._exit(1)
    else:
        os.waitpid(pid, 0)
    os.close(fd)
except Exception as e:
    pass
" 2>/dev/null || true

    sleep 1

    AFTER=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)
    NEW_LINES=$((AFTER - BEFORE))

    if [ $NEW_LINES -gt 0 ] && tail -n $NEW_LINES "$LOGFILE" | grep -q '"type":"security_execveat"'; then
        echo -e "${GREEN}PASS${NC}"
        ((PASSED++))
        # Show the event
        tail -n $NEW_LINES "$LOGFILE" | grep '"type":"security_execveat"' | head -1 | python3 -m json.tool 2>/dev/null || true
    else
        echo -e "${YELLOW}SKIP${NC} (execveat not triggered - may depend on Python/glibc version)"
        ((SKIPPED++))
    fi
}

# Test 7: bpf() detection (T1014 - eBPF Rootkit)
# Note: We don't actually load a BPF program (requires CAP_BPF)
# Instead we verify the BPF programs are attached
test_bpf_attachment() {
    echo -n "Testing bpf() monitoring attachment (T1014)... "

    # Check if the BPF programs are attached by looking at startup output
    if journalctl -u linmond --since "10 minutes ago" 2>/dev/null | grep -q "BPF monitoring"; then
        echo -e "${GREEN}PASS${NC} (BPF program attached)"
        ((PASSED++))
    else
        # Just check that linmond is running - bpf monitoring is best-effort
        echo -e "${YELLOW}SKIP${NC} (cannot verify without loading BPF program)"
        ((SKIPPED++))
    fi
}

# Check which tests to run based on config
check_config() {
    local option=$1
    if grep -q "^${option} *= *true" /etc/linmon/linmon.conf 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

echo "Checking enabled security monitoring features..."
echo ""

# Run tests based on config
if check_config "monitor_ptrace"; then
    test_ptrace
    echo ""
else
    echo -e "${YELLOW}SKIP${NC} ptrace test (monitor_ptrace not enabled in config)"
    ((SKIPPED++))
fi

if check_config "monitor_memfd"; then
    test_memfd
    echo ""
else
    echo -e "${YELLOW}SKIP${NC} memfd test (monitor_memfd not enabled in config)"
    ((SKIPPED++))
fi

if check_config "monitor_modules"; then
    test_module_attachment
    echo ""
else
    echo -e "${YELLOW}SKIP${NC} module test (monitor_modules not enabled in config)"
    ((SKIPPED++))
fi

if check_config "monitor_bind"; then
    test_bind
    echo ""
else
    echo -e "${YELLOW}SKIP${NC} bind test (monitor_bind not enabled in config)"
    ((SKIPPED++))
fi

if check_config "monitor_unshare"; then
    test_unshare
    echo ""
else
    echo -e "${YELLOW}SKIP${NC} unshare test (monitor_unshare not enabled in config)"
    ((SKIPPED++))
fi

if check_config "monitor_execveat"; then
    test_execveat
    echo ""
else
    echo -e "${YELLOW}SKIP${NC} execveat test (monitor_execveat not enabled in config)"
    ((SKIPPED++))
fi

if check_config "monitor_bpf"; then
    test_bpf_attachment
    echo ""
else
    echo -e "${YELLOW}SKIP${NC} bpf test (monitor_bpf not enabled in config)"
    ((SKIPPED++))
fi

echo ""
echo "=== Test Summary ==="
echo -e "Passed:  ${GREEN}$PASSED${NC}"
echo -e "Failed:  ${RED}$FAILED${NC}"
echo -e "Skipped: ${YELLOW}$SKIPPED${NC}"

if [ $FAILED -gt 0 ]; then
    echo ""
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
elif [ $PASSED -eq 0 ] && [ $SKIPPED -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}All tests skipped. Enable security monitoring in /etc/linmon/linmon.conf:${NC}"
    echo "  monitor_ptrace = true    # T1055 Process Injection"
    echo "  monitor_modules = true   # T1547.006 Kernel Modules"
    echo "  monitor_memfd = true     # T1620 Fileless Malware"
    echo "  monitor_bind = true      # T1571 Bind Shell / C2"
    echo "  monitor_unshare = true   # T1611 Container Escape"
    echo "  monitor_execveat = true  # T1620 Fileless Execution"
    echo "  monitor_bpf = true       # T1014 eBPF Rootkit"
    echo ""
    echo "Then reload: sudo systemctl reload linmond"
    exit 0
else
    echo ""
    echo -e "${GREEN}All enabled tests passed!${NC}"
    exit 0
fi
