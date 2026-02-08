# Security Fixes - Log File and Config Validation

## Summary

Fixed two Medium-severity security vulnerabilities related to log file permissions and config file validation.

## Issue #1: Insecure File Permissions on SIGHUP Log Reload

**Severity**: Medium
**Impact**: Log files created during SIGHUP reload could expose sensitive event data

### Problem

When LinMon received SIGHUP to reload configuration, the new log file was opened using `fopen(new_log_file, "a")` without setting proper permissions. This could create new log files with permissions inherited from the process umask (potentially world-readable), exposing sensitive security event data.

Initial `logger_init()` correctly used `umask(0077)` and `chmod(log_file, 0640)`, but SIGHUP reload path in `main.c:1516` did not.

### Fix

1. Created new function `logger_open_file_secure()` in `src/logger.c` that:
   - Sets restrictive umask (0077) before opening
   - Explicitly chmod to 0640 after opening
   - Restores original umask
   - Sets line buffering

2. Refactored `logger_init()` to use this function

3. Updated SIGHUP handler in `src/main.c` to use `logger_open_file_secure()` instead of `fopen()`

### Files Modified

- `src/logger.c` - Added `logger_open_file_secure()` helper function
- `src/logger.h` - Exported new function
- `src/main.c` - SIGHUP handler now uses secure file opening

## Issue #2: Weak Config File Ownership Validation

**Severity**: Medium
**Impact**: Privilege escalation vector through malicious config files

### Problem

Config file validation only warned about non-root ownership and group-writable permissions, but did not abort. Since:
1. Config is read before privilege drop (daemon runs as root)
2. Config controls log file path (`log_file` setting)
3. Log file is opened/chmod'd as root (`src/logger.c:55,64`)

An attacker who controls a non-root config file could:
- Set `log_file` to arbitrary path (e.g., `/etc/shadow`)
- Cause daemon to chmod that file to 0640
- Privilege escalation

### Fix

Changed warnings to hard failures in `src/config.c`:

**Before**:
```c
if (st.st_uid != 0) {
    fprintf(stderr, "Warning: Config file not owned by root...\n");
    // continues anyway
}
```

**After**:
```c
if (st.st_uid != 0) {
    fprintf(stderr, "CRITICAL: Config file not owned by root (uid=%d): %s\n",
            st.st_uid, config_file);
    fprintf(stderr, "Fix with: chown root:root %s\n", config_file);
    return -EPERM;  // Hard fail
}
```

Added test mode bypass (via `LINMON_TEST_MODE` env var) to allow unit tests to use temporary non-root configs.

### Files Modified

- `src/config.c` - Hard fail on non-root ownership and group-writable
- `Makefile` - Set `LINMON_TEST_MODE=1` when running tests

## Production Requirements

After these fixes, production config files MUST:
- Be owned by root (uid=0)
- NOT be group-writable
- NOT be world-writable

Example:
```bash
sudo chown root:root /etc/linmon/linmon.conf
sudo chmod 0600 /etc/linmon/linmon.conf
```

## Testing

Added comprehensive test coverage:

```bash
# Security-specific tests
./test_security_fixes.sh

# Full test suite (includes config validation)
make test
```

All 86 existing unit tests pass with new security restrictions.

## Defense in Depth

These fixes complement existing security measures:
- Privilege dropping to nobody:nogroup after BPF load
- Restrictive directory permissions (0750 on /var/log/linmon/)
- Capability restrictions (only CAP_SYS_PTRACE retained)
- Immutable flags on binary and config (chattr +i)

## References

- OWASP: Insecure File Permissions
- CWE-732: Incorrect Permission Assignment for Critical Resource
- CWE-266: Incorrect Privilege Assignment
