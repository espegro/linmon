# LinMon Security Hardening Design

**Date**: 2026-02-20
**Status**: Approved
**Author**: Security audit findings review

## Executive Summary

This design addresses three critical security vulnerabilities identified in LinMon:
1. **CRITICAL**: Symlink attacks via nobody-writable directories and unsafe file operations
2. **MEDIUM**: Shared `nobody` account enabling DoS/tampering via unauthorized signals
3. **LOW**: Command injection in query script via grep option parsing

All fixes follow "secure by default" principles and include automatic migration for existing installations.

---

## 1. Security Model & User Management

### Objective
Replace hardcoded `nobody` (UID 65534) with dedicated `linmon` system user to provide isolation from other services.

### User Creation Strategy
- **System user**: `linmon` (auto-assigned UID, typically 300-999)
- **No home directory**, no login shell (`/usr/sbin/nologin`)
- **Primary group**: `linmon` (auto-created, matches UID)
- **Created in**: `install.sh` before directory ownership changes

### Migration Path (Automatic, Idempotent)

**install.sh sequence**:
```bash
1. Check if linmon user exists → create if missing (useradd --system)
2. Check if daemon is running → systemctl stop linmond (if active)
3. Create/update directories with linmon ownership
4. Recursively chown existing files: /var/log/linmon, /var/cache/linmon
5. [SELinux] Restore file contexts after ownership change
6. Install binary
7. Restart daemon if was previously running
```

### SELinux Considerations (RHEL/Rocky/Fedora)

**File Contexts**: SELinux contexts are path-based, but we must restore after ownership changes:
```bash
# After chown operations:
if command -v restorecon >/dev/null 2>&1; then
    if sestatus 2>/dev/null | grep -q "SELinux status:.*enabled"; then
        restorecon -R /var/log/linmon /var/cache/linmon
    fi
fi
```

**Why this matters**:
- Type context (`var_log_t`, `var_cache_t`) is path-based (survives chown)
- User context may need adjustment for new owner
- `restorecon -R` ensures contexts match policy for new ownership

**Process Context**:
- Daemon's SELinux domain determined by binary context (not user)
- Existing `restorecon /usr/local/sbin/linmond` already handles this
- No custom policy needed - daemon runs in `unconfined_service_t` (same as before)

### Code Changes

**src/main.c** (lines ~1360, 1388):
```c
// OLD:
if (setgid(65534) != 0) { ... }  // nobody group
if (setuid(65534) != 0) { ... }  // nobody user

// NEW:
struct passwd *linmon_user = getpwnam("linmon");
if (!linmon_user) {
    fprintf(stderr, "CRITICAL: linmon user not found. Run install.sh first.\n");
    goto cleanup;
}
if (setgid(linmon_user->pw_gid) != 0) { ... }
if (setuid(linmon_user->pw_uid) != 0) { ... }
```

### Idempotency Guarantee
Running `install.sh` multiple times is safe:
- `useradd` with `|| true` (ignore if user exists)
- `chown -R` resets ownership even if already correct
- `restorecon -R` reapplies correct contexts
- Systemd reload handles running → stopped → running transition

### Backwards Compatibility
**None**. After upgrade, all files owned by `linmon:linmon`. Rollback requires manual `chown` back to `nobody:nogroup`.

---

## 2. Symlink Attack Mitigation

### Objective
Prevent attackers from using symlinks in linmon-owned directories to manipulate arbitrary files during daemon startup.

### Root Cause
`fopen()` follows symlinks, and files are opened as root before privilege drop.

### Attack Scenario (Before Fix)
```bash
# Attacker running as nobody (any service/container using UID 65534)
ln -s /etc/shadow /var/log/linmon/events.json
ln -s /etc/passwd /var/cache/linmon/hash.cache

# linmond restarts (systemctl restart linmond)
# Result: /etc/shadow is now mode 0640, readable by attacker
```

### Solution
Create `safe_fopen()` wrapper that uses `open()` with `O_NOFOLLOW`.

### Implementation

**New files**: `src/utils.c` + `src/utils.h`

**src/utils.h**:
```c
#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <sys/types.h>

// Safe file opening with symlink protection
// Returns NULL on error (errno set), includes ELOOP for symlink detection
FILE *safe_fopen(const char *path, const char *mode, mode_t perms);

#endif
```

**src/utils.c**:
```c
#include "utils.h"
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

FILE *safe_fopen(const char *path, const char *mode, mode_t perms) {
    int flags = O_NOFOLLOW | O_CLOEXEC;

    // Parse mode string (supports "r", "w", "a")
    if (strchr(mode, 'a'))
        flags |= O_WRONLY | O_APPEND | O_CREAT;
    else if (strchr(mode, 'w'))
        flags |= O_WRONLY | O_TRUNC | O_CREAT;
    else if (strchr(mode, 'r'))
        flags |= O_RDONLY;
    else {
        errno = EINVAL;
        return NULL;
    }

    int fd = open(path, flags, perms);
    if (fd == -1) return NULL;  // errno preserved (ELOOP if symlink)

    FILE *fp = fdopen(fd, mode);
    if (!fp) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
    }
    return fp;
}
```

### Affected Files (Replace fopen() with safe_fopen())

1. **logger.c:70** - Log file creation
   ```c
   // OLD: FILE *fp = fopen(log_file, "a");
   // NEW:
   FILE *fp = safe_fopen(log_file, "a", 0640);
   if (!fp) {
       if (errno == ELOOP)
           syslog(LOG_ERR, "SECURITY: Symlink attack detected on log file: %s", log_file);
       return -errno;
   }
   ```

2. **filehash.c:285** - Hash cache file
   ```c
   // OLD: fp = fopen(tmp_path, "w");
   // NEW:
   fp = safe_fopen(tmp_path, "w", 0600);
   if (!fp) {
       if (errno == ELOOP)
           syslog(LOG_ERR, "SECURITY: Symlink attack detected on hash cache: %s", tmp_path);
       return -errno;
   }
   ```

3. **pkgcache.c:506** - Package cache file
   ```c
   // OLD: fp = fopen(tmp_path, "w");
   // NEW:
   fp = safe_fopen(tmp_path, "w", 0600);
   if (!fp) {
       if (errno == ELOOP)
           syslog(LOG_ERR, "SECURITY: Symlink attack detected on package cache: %s", tmp_path);
       return -errno;
   }
   ```

### Build System Changes

**Makefile** - Add `src/utils.c` to compilation:
```make
DAEMON_SOURCES = src/main.c src/logger.c src/config.c src/filter.c \
                 src/userdb.c src/filehash.c src/procfs.c src/pkgcache.c \
                 src/authcheck.c src/utils.c
```

### Error Handling
Check for `errno == ELOOP` to distinguish symlink attacks from other errors:
- Log to syslog with SECURITY prefix for monitoring
- Return error to caller (daemon startup fails safely)
- Creates audit trail in journald for incident response

---

## 3. Signal Sender Validation

### Objective
Prevent unauthorized processes (including compromised services running as `linmon`) from sending SIGHUP/SIGTERM to the daemon.

### Access Control Policy
**Only root (UID 0) may signal the daemon.**

### Rationale
- Daemon is controlled by systemd (runs as root)
- `systemctl reload linmond` → SIGHUP from PID 1 (UID 0) ✓
- `systemctl stop linmond` → SIGTERM from PID 1 (UID 0) ✓
- No legitimate use case for non-root signals

### Implementation

**src/main.c:sig_handler_info()** - Add sender validation:

```c
// Enhanced signal handler with sender validation (anti-tampering)
static void sig_handler_info(int sig, siginfo_t *info, void *ucontext)
{
    (void)ucontext;

    last_signal = sig;
    if (info) {
        signal_sender_pid = info->si_pid;
        signal_sender_uid = info->si_uid;
    }

    // Validate sender for security-critical signals
    if (sig == SIGHUP || sig == SIGTERM) {
        if (info && info->si_uid != 0) {
            // Log rejection with full context for forensics
            syslog(LOG_WARNING, "SECURITY: Rejected signal %d from unauthorized UID %d (PID %d)",
                   sig, (int)info->si_uid, (int)info->si_pid);

            // TODO: Log to JSON as security event (if logger initialized)
            // This creates an audit trail of signal attacks
            return;  // Ignore signal
        }
    }

    // Process authorized signal
    if (sig == SIGINT || sig == SIGTERM) {
        exiting = true;
    } else if (sig == SIGHUP) {
        reload_config = true;
    }
}
```

### Logging Enhancement
Rejected signals appear in two places:
1. **Syslog/journald**: Immediate visibility for monitoring (`journalctl -u linmond`)
2. **JSON events log**: Audit trail for SIEM correlation (future enhancement)

### Edge Cases
- **info == NULL**: Shouldn't happen with `SA_SIGINFO`, but handle defensively (allow signal if can't verify sender)
- **Signal from PID 0**: Kernel signal (e.g., SIGTERM on shutdown) - info->si_pid == 0, allow
- **SIGINT (Ctrl+C)**: Typically from controlling terminal (UID varies) - keep current behavior (no validation)

### Testing
```bash
# As root - should work:
sudo systemctl reload linmond     # SIGHUP accepted
sudo kill -HUP $(pidof linmond)   # SIGHUP accepted

# As non-root - should be rejected:
sudo -u linmon kill -HUP $(pidof linmond)  # SIGHUP rejected, logged
```

---

## 4. Grep Option Injection Fix

### Objective
Prevent command-line option injection in `linmon-query.sh` search function.

### Vulnerability
User-controlled `$pattern` is passed to grep without `--` separator:
```bash
grep -i "$pattern" "$LOGFILE"  # BAD: pattern="-v password" inverts match
```

### Exploit Examples
```bash
./linmon-query.sh search "-v password"     # Inverts match (shows non-password lines)
./linmon-query.sh search "-f /etc/shadow"  # Reads patterns from /etc/shadow
```

### Fix
Add `--` separator to terminate option parsing:

**linmon-query.sh:165** - Add `--` to grep command:
```bash
cmd_search() {
    local pattern="$1"
    echo "=== Search Results for: $pattern (last $LIMIT) ==="
    grep -i -- "$pattern" "$LOGFILE" | tail -n "$LIMIT" | jq '.'
}
```

### Security Properties
- **Option injection blocked**: `--` prevents `-f`, `-v`, `-e`, etc. from being interpreted
- **Regex still works**: `.*`, `^foo$`, `[a-z]+` remain functional (intentional)
- **Minimal change**: Single `--` addition, no behavior change for legitimate queries

### Testing
```bash
# Legitimate queries still work:
./linmon-query.sh search "process_exec"      # ✓ Works
./linmon-query.sh search "ssh.*connect"      # ✓ Regex works

# Injection attempts now fail safely:
./linmon-query.sh search "-v password"       # ✓ Searches for literal "-v password"
./linmon-query.sh search "-f /etc/shadow"    # ✓ Searches for literal string
```

### Other grep Calls (Audited, Safe)
- `linmon-query.sh:169` - Hardcoded pattern `'.username // "system"'` (no user input)
- Other uses have hardcoded patterns or validated input

---

## Implementation Plan Overview

1. **Create utils.c/utils.h** - Safe file opening wrapper
2. **Update install.sh** - Add linmon user creation and migration logic
3. **Update src/main.c** - Replace UID 65534 with getpwnam("linmon"), add signal validation
4. **Update logger.c, filehash.c, pkgcache.c** - Replace fopen() with safe_fopen()
5. **Update linmon-query.sh** - Add `--` to grep command
6. **Update Makefile** - Add utils.c to build
7. **Test on Ubuntu 24.04 and RHEL 9** - Verify migration and SELinux
8. **Update documentation** - SECURITY.md, CHANGELOG.md

## Security Impact

| Finding | Before | After | Risk Reduction |
|---------|--------|-------|----------------|
| Symlink attack | Any process as nobody can manipulate files via symlinks | Symlinks rejected (ELOOP), daemon fails safely | CRITICAL → Mitigated |
| Signal DoS | Any process as nobody can reload/stop daemon | Only root can signal daemon | MEDIUM → Mitigated |
| grep injection | Pattern can inject options (-f, -v) | Pattern treated as literal after -- | LOW → Mitigated |

## Rollback Plan

If issues arise:
1. Stop daemon: `systemctl stop linmond`
2. Revert to previous version
3. Change ownership back: `chown -R nobody:nogroup /var/log/linmon /var/cache/linmon`
4. Restart: `systemctl start linmond`

Note: Dedicated `linmon` user can remain (harmless if unused).
