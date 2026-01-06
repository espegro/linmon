# LinMon Test Scripts

This directory contains test scripts for LinMon v1.4.0 security detection features.

## Overview

LinMon v1.4.0 introduces three new security detection capabilities:

1. **SSH Key Detection** (T1552.004, T1098.004) - Detects reads of SSH private keys and writes to authorized_keys
2. **SUID/SGID Manipulation** (T1548.001) - Detects chmod operations that set SUID/SGID bits
3. **Persistence Mechanisms** (T1053, T1547) - Detects writes to cron, systemd, shell profiles, init scripts, autostart

These test scripts verify that each feature is working correctly.

## Prerequisites

### 1. LinMon Must Be Running

```bash
sudo systemctl status linmond
```

If not running:
```bash
sudo systemctl start linmond
```

### 2. Enable Detection Features

Edit `/etc/linmon/linmon.conf` and enable the features you want to test:

```ini
# SSH key detection (enabled by default)
monitor_cred_read = true

# SUID/SGID manipulation detection
monitor_suid = true

# Persistence mechanism detection
monitor_persistence = true
```

Reload configuration:
```bash
sudo systemctl reload linmond
```

### 3. Required Tools

All test scripts require:
- `jq` - JSON parsing
- `systemctl` - Service management

Install on Ubuntu/Debian:
```bash
sudo apt-get install jq
```

Install on RHEL/Rocky:
```bash
sudo dnf install jq
```

## Running Tests

### Run All Tests (Recommended)

```bash
# User-level tests only
./run_all_tests.sh

# All tests (requires root for SUID, cron, systemd tests)
sudo ./run_all_tests.sh
```

The master test runner will:
- Check if LinMon is running
- Run all three feature tests in sequence
- Display pass/fail results for each test
- Print a summary with troubleshooting steps if needed

### Run Individual Tests

#### Test 1: SSH Key Detection

Tests detection of:
- SSH private key reads (`~/.ssh/id_rsa`, `id_ed25519`, `id_ecdsa`)
- SSH authorized_keys writes (`~/.ssh/authorized_keys`)
- SSH config reads (`~/.ssh/config`)

```bash
./test_ssh_keys.sh
```

**Expected events**: `security_cred_read` with `cred_file` values:
- `ssh_private_key`
- `ssh_authorized_keys`
- `ssh_user_config`

#### Test 2: SUID/SGID Manipulation

Tests detection of:
- SUID bit setting (`chmod u+s`)
- SGID bit setting (`chmod g+s`)
- Both SUID and SGID (`chmod ug+s`)

```bash
sudo ./test_suid.sh
```

**Requires root**: SUID/SGID operations require root privileges.

**Expected events**: `security_suid` with fields:
- `suid: true` (SUID bit set)
- `sgid: true` (SGID bit set)
- `mode` (full mode bits)
- `path` (binary path)

#### Test 3: Persistence Mechanism Detection

Tests detection of:
- Cron job creation (`/etc/cron.d/*`)
- Systemd service creation (`/etc/systemd/system/*`)
- Shell profile modification (`~/.bashrc`)
- Autostart entry creation (`~/.config/autostart/*`)

```bash
# User-level tests only (shell profile, autostart)
./test_persistence.sh

# All tests (requires root for cron, systemd)
sudo ./test_persistence.sh
```

**Expected events**: `security_persistence` with `persistence_type` values:
- `cron`
- `systemd`
- `shell_profile`
- `autostart`

## Verifying Results

### Check Events in JSON Log

View all security events from the last test run:

```bash
# SSH key events
sudo tail -20 /var/log/linmon/events.json | jq 'select(.type == "security_cred_read" and (.cred_file | test("ssh")))'

# SUID events
sudo tail -20 /var/log/linmon/events.json | jq 'select(.type == "security_suid")'

# Persistence events
sudo tail -20 /var/log/linmon/events.json | jq 'select(.type == "security_persistence")'
```

### Expected Event Examples

**SSH Private Key Read**:
```json
{
  "timestamp": "2026-01-06T12:34:56.789Z",
  "type": "security_cred_read",
  "cred_file": "ssh_private_key",
  "path": "/home/user/.ssh/id_rsa",
  "uid": 1000,
  "username": "user",
  "comm": "cat"
}
```

**SUID Manipulation**:
```json
{
  "timestamp": "2026-01-06T12:34:56.789Z",
  "type": "security_suid",
  "path": "/tmp/linmon_test_suid",
  "mode": 35309,
  "suid": true,
  "sgid": false,
  "uid": 0,
  "username": "root",
  "comm": "chmod"
}
```

**Persistence Detection**:
```json
{
  "timestamp": "2026-01-06T12:34:56.789Z",
  "type": "security_persistence",
  "persistence_type": "cron",
  "path": "/etc/cron.d/linmon_test",
  "uid": 0,
  "username": "root",
  "comm": "bash",
  "open_flags": 577
}
```

## Troubleshooting

### No Events Logged

1. **Check LinMon is running**:
   ```bash
   sudo systemctl status linmond
   ```

2. **Check configuration**:
   ```bash
   grep -E "monitor_cred_read|monitor_suid|monitor_persistence" /etc/linmon/linmon.conf
   ```

3. **Reload configuration**:
   ```bash
   sudo systemctl reload linmond
   ```

4. **Check for errors**:
   ```bash
   sudo journalctl -u linmond -n 50
   ```

### Tests Fail with "Permission Denied"

Some tests require root privileges:
- `test_suid.sh` - SUID operations require root
- `test_persistence.sh` - Cron and systemd tests require root

Run with sudo:
```bash
sudo ./test_suid.sh
sudo ./test_persistence.sh
```

### Events Logged But Not Detected by Test

The test scripts look for events logged **after** the test starts. If you run tests multiple times quickly, old events may be present.

Wait a few seconds between test runs or check manually:
```bash
sudo tail -100 /var/log/linmon/events.json | jq 'select(.type == "security_persistence")'
```

## Cleanup

All test scripts clean up after themselves:

- **SSH test**: Removes test SSH keys and authorized_keys entries
- **SUID test**: Removes test binaries from `/tmp`
- **Persistence test**: Removes cron jobs, systemd services, shell profile entries, autostart files

If a test is interrupted (Ctrl+C), you may need to manually clean up:

```bash
# Remove test SSH key
rm -f ~/.ssh/test_linmon_id_rsa*

# Remove test binaries
sudo rm -f /tmp/linmon_test_*

# Remove test cron job
sudo rm -f /etc/cron.d/linmon_test

# Remove test systemd service
sudo rm -f /etc/systemd/system/linmon-test.service
sudo systemctl daemon-reload

# Remove test entries from .bashrc
sed -i '/LinMon test/d' ~/.bashrc
sed -i '/LINMON_TEST/d' ~/.bashrc

# Remove test autostart entry
rm -f ~/.config/autostart/linmon-test.desktop
```

## Integration with CI/CD

These test scripts can be integrated into CI/CD pipelines:

```bash
#!/bin/bash
# Example CI test script

# Start LinMon
sudo systemctl start linmond
sleep 2

# Enable all features
sudo sed -i 's/^monitor_cred_read =.*/monitor_cred_read = true/' /etc/linmon/linmon.conf
sudo sed -i 's/^monitor_suid =.*/monitor_suid = true/' /etc/linmon/linmon.conf
sudo sed -i 's/^monitor_persistence =.*/monitor_persistence = true/' /etc/linmon/linmon.conf
sudo systemctl reload linmond
sleep 2

# Run tests
cd tests/
sudo ./run_all_tests.sh

# Check exit code
if [ $? -eq 0 ]; then
    echo "All LinMon v1.4.0 tests passed"
    exit 0
else
    echo "LinMon v1.4.0 tests failed"
    exit 1
fi
```

## Security Note

These tests intentionally trigger security detections. When run on production systems:

1. **Review test artifacts** - Ensure all test files are cleaned up
2. **Inform security team** - Test activity may trigger SIEM alerts
3. **Test in staging first** - Validate tests work before production deployment

## Support

If tests fail or you encounter issues:

1. Check [MONITORING.md](../MONITORING.md) for event format examples
2. Check [SECURITY.md](../SECURITY.md) for MITRE ATT&CK coverage details
3. Check [CHANGELOG.md](../CHANGELOG.md) for v1.4.0 feature documentation
4. Open an issue at: https://github.com/espegro/linmon/issues
