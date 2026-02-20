# Security Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement security fixes for symlink attacks, shared user DoS, and grep injection vulnerabilities.

**Architecture:** Add safe_fopen() wrapper with O_NOFOLLOW, migrate from nobody (UID 65534) to dedicated linmon system user, add signal sender validation, fix grep option injection.

**Tech Stack:** C (POSIX), Bash, SELinux-aware installation

---

## Task 1: Create Safe File Opening Utility

**Files:**
- Create: `src/utils.h`
- Create: `src/utils.c`
- Create: `tests/test_utils.c`

### Step 1: Write test for safe_fopen with regular file

**Create:** `tests/test_utils.c`

```c
#include "test_framework.h"
#include "../src/utils.h"
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

void test_safe_fopen_create_regular_file(void) {
    const char *path = "/tmp/linmon_test_regular.txt";

    // Clean up from previous test
    unlink(path);

    // Open file for writing
    FILE *fp = safe_fopen(path, "w", 0600);
    ASSERT_TRUE(fp != NULL);

    fprintf(fp, "test content\n");
    fclose(fp);

    // Verify file was created with correct permissions
    struct stat st;
    ASSERT_EQ(stat(path, &st), 0);
    ASSERT_EQ(st.st_mode & 0777, 0600);

    // Clean up
    unlink(path);
}

void test_safe_fopen_append_mode(void) {
    const char *path = "/tmp/linmon_test_append.txt";

    // Clean up from previous test
    unlink(path);

    // Create initial file
    FILE *fp1 = safe_fopen(path, "w", 0640);
    ASSERT_TRUE(fp1 != NULL);
    fprintf(fp1, "line1\n");
    fclose(fp1);

    // Append to file
    FILE *fp2 = safe_fopen(path, "a", 0640);
    ASSERT_TRUE(fp2 != NULL);
    fprintf(fp2, "line2\n");
    fclose(fp2);

    // Verify both lines present
    FILE *fp3 = fopen(path, "r");
    char buf[100];
    fgets(buf, sizeof(buf), fp3);
    ASSERT_STREQ(buf, "line1\n");
    fgets(buf, sizeof(buf), fp3);
    ASSERT_STREQ(buf, "line2\n");
    fclose(fp3);

    // Clean up
    unlink(path);
}

void test_safe_fopen_rejects_symlink(void) {
    const char *target = "/tmp/linmon_test_target.txt";
    const char *link = "/tmp/linmon_test_symlink.txt";

    // Clean up from previous test
    unlink(target);
    unlink(link);

    // Create target file
    FILE *fp_target = fopen(target, "w");
    fprintf(fp_target, "target content\n");
    fclose(fp_target);

    // Create symlink
    ASSERT_EQ(symlink(target, link), 0);

    // Attempt to open symlink - should fail with ELOOP
    errno = 0;
    FILE *fp = safe_fopen(link, "a", 0640);
    ASSERT_TRUE(fp == NULL);
    ASSERT_EQ(errno, ELOOP);

    // Clean up
    unlink(link);
    unlink(target);
}

void test_safe_fopen_invalid_mode(void) {
    const char *path = "/tmp/linmon_test_invalid.txt";

    // Invalid mode should fail with EINVAL
    errno = 0;
    FILE *fp = safe_fopen(path, "x", 0600);
    ASSERT_TRUE(fp == NULL);
    ASSERT_EQ(errno, EINVAL);
}

int main(void) {
    TEST_BEGIN("utils");

    RUN_TEST(test_safe_fopen_create_regular_file);
    RUN_TEST(test_safe_fopen_append_mode);
    RUN_TEST(test_safe_fopen_rejects_symlink);
    RUN_TEST(test_safe_fopen_invalid_mode);

    TEST_END();
}
```

### Step 2: Update Makefile to build test

**Modify:** `Makefile` (add test target)

Find the test targets section and add:

```make
build/tests/test_utils: tests/test_utils.c src/utils.c
	mkdir -p build/tests
	gcc -Wall -Wextra -O2 -g -I$(INCLUDE_DIRS) -Ibpf -Isrc tests/test_utils.c src/utils.c -o build/tests/test_utils

test: build/tests/test_config build/tests/test_filter build/tests/test_logger \
      build/tests/test_filehash build/tests/test_pkgcache build/tests/test_procfs \
      build/tests/test_utils
	@echo "Running unit tests..."
	@./build/tests/test_config
	@./build/tests/test_filter
	@./build/tests/test_logger
	@./build/tests/test_filehash
	@./build/tests/test_pkgcache
	@./build/tests/test_procfs
	@./build/tests/test_utils
	@echo ""
	@echo "=============================="
	@echo "All tests passed!"
```

### Step 3: Run test to verify it fails

```bash
make build/tests/test_utils
./build/tests/test_utils
```

**Expected:** Compilation fails with "utils.h: No such file or directory"

### Step 4: Create utils.h header

**Create:** `src/utils.h`

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

### Step 5: Create utils.c implementation

**Create:** `src/utils.c`

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

### Step 6: Run test to verify it passes

```bash
make build/tests/test_utils
./build/tests/test_utils
```

**Expected:** All 4 tests pass

### Step 7: Add utils.c to daemon build

**Modify:** `Makefile`

Find `DAEMON_SOURCES` and add `src/utils.c`:

```make
DAEMON_SOURCES = src/main.c src/logger.c src/config.c src/filter.c \
                 src/userdb.c src/filehash.c src/procfs.c src/pkgcache.c \
                 src/authcheck.c src/containerinfo.c src/utils.c
```

### Step 8: Rebuild daemon to verify utils.c compiles

```bash
make clean
make
```

**Expected:** Build succeeds, `build/linmond` created

### Step 9: Commit safe_fopen utility

```bash
git add src/utils.h src/utils.c tests/test_utils.c Makefile
git commit -m "feat: Add safe_fopen() wrapper with O_NOFOLLOW symlink protection

- Implements safe file opening that rejects symlinks (returns ELOOP)
- Supports modes: r, w, a with configurable permissions
- Includes comprehensive unit tests for regular files, append, symlinks
- Prevents TOCTOU symlink attacks during file creation"
```

---

## Task 2: Update Logger to Use safe_fopen

**Files:**
- Modify: `src/logger.c:66-76`

### Step 1: Add syslog.h include to logger.c

**Modify:** `src/logger.c` (top of file, after existing includes)

```c
#include <syslog.h>
```

### Step 2: Update logger.c to use safe_fopen

**Modify:** `src/logger.c:66-76` in `logger_open_file_secure()` function

**Replace:**
```c
    // Set restrictive umask for log file creation (prevents world-readable files)
    mode_t old_umask = umask(0077);

    FILE *fp = fopen(log_file, "a");
    if (!fp) {
        int saved_errno = errno;
        umask(old_umask);  // Restore umask before returning
        errno = saved_errno;
        return NULL;
    }

    // Set permissions to 0640 (rw-r-----) for defense in depth
    // Even though directory is 0750, file should also have restrictive permissions
    chmod(log_file, 0640);
```

**With:**
```c
    // Set restrictive umask for log file creation (prevents world-readable files)
    mode_t old_umask = umask(0077);

    FILE *fp = safe_fopen(log_file, "a", 0640);
    if (!fp) {
        int saved_errno = errno;
        umask(old_umask);  // Restore umask before returning

        // Detect symlink attack
        if (saved_errno == ELOOP) {
            syslog(LOG_ERR, "SECURITY: Symlink attack detected on log file: %s", log_file);
        }

        errno = saved_errno;
        return NULL;
    }
```

Note: Remove the separate `chmod()` call since safe_fopen now sets permissions atomically.

### Step 3: Add utils.h include to logger.c

**Modify:** `src/logger.c` (top of file, after existing includes)

```c
#include "utils.h"
```

### Step 4: Build and verify

```bash
make clean
make
```

**Expected:** Build succeeds

### Step 5: Test logger with symlink attack simulation

```bash
# Manual test (requires root):
sudo mkdir -p /tmp/linmon_test_log
sudo ln -s /etc/shadow /tmp/linmon_test_log/events.json

# Edit linmon.conf temporarily to use /tmp/linmon_test_log/events.json
# Run daemon - should fail with SECURITY error in syslog

sudo ./build/linmond -c linmon.conf
# Check journalctl for "SECURITY: Symlink attack detected"

# Clean up
sudo rm /tmp/linmon_test_log/events.json
sudo rmdir /tmp/linmon_test_log
```

**Expected:** Daemon logs SECURITY error and refuses to start

### Step 6: Commit logger changes

```bash
git add src/logger.c
git commit -m "fix: Use safe_fopen in logger to prevent symlink attacks

- Replace fopen() with safe_fopen() in logger_open_file_secure()
- Detect symlink attacks via ELOOP errno
- Log SECURITY event to syslog when attack detected
- Permissions now set atomically during file creation"
```

---

## Task 3: Update File Hash Cache to Use safe_fopen

**Files:**
- Modify: `src/filehash.c:282-290`

### Step 1: Add utils.h and syslog.h includes

**Modify:** `src/filehash.c` (top of file, after existing includes)

```c
#include "utils.h"
#include <syslog.h>
```

### Step 2: Update filehash.c to use safe_fopen

**Modify:** `src/filehash.c:282-290` in `filehash_save()` function

**Replace:**
```c
    // Set restrictive umask before file creation (prevents world-readable files)
    mode_t old_umask = umask(0077);

    fp = fopen(tmp_path, "w");
    if (!fp) {
        int saved_errno = errno;
        umask(old_umask);  // Restore umask before returning
        return -saved_errno;
    }

    // Set restrictive permissions (0600) for defense in depth
    // Even though umask is 0077, explicitly set permissions to ensure correctness
    if (fchmod(fileno(fp), 0600) != 0) {
        int saved_errno = errno;
        umask(old_umask);  // Restore umask before error return
        fclose(fp);
        unlink(tmp_path);
        return -saved_errno;
    }
```

**With:**
```c
    // Set restrictive umask before file creation (prevents world-readable files)
    mode_t old_umask = umask(0077);

    fp = safe_fopen(tmp_path, "w", 0600);
    if (!fp) {
        int saved_errno = errno;
        umask(old_umask);  // Restore umask before returning

        // Detect symlink attack
        if (saved_errno == ELOOP) {
            syslog(LOG_ERR, "SECURITY: Symlink attack detected on hash cache: %s", tmp_path);
        }

        return -saved_errno;
    }
```

Note: Remove the separate `fchmod()` block since safe_fopen sets permissions atomically.

### Step 3: Build and verify

```bash
make clean
make
```

**Expected:** Build succeeds

### Step 4: Commit filehash changes

```bash
git add src/filehash.c
git commit -m "fix: Use safe_fopen in filehash to prevent symlink attacks

- Replace fopen() with safe_fopen() in filehash_save()
- Detect symlink attacks via ELOOP errno
- Log SECURITY event to syslog when attack detected
- Remove redundant fchmod() call (permissions set atomically)"
```

---

## Task 4: Update Package Cache to Use safe_fopen

**Files:**
- Modify: `src/pkgcache.c:503-525`

### Step 1: Add utils.h and syslog.h includes

**Modify:** `src/pkgcache.c` (top of file, after existing includes)

```c
#include "utils.h"
#include <syslog.h>
```

### Step 2: Update pkgcache.c to use safe_fopen

**Modify:** `src/pkgcache.c:503-525` in `pkgcache_save()` function

**Replace:**
```c
    // Set restrictive umask before file creation (prevents world-readable files)
    mode_t old_umask = umask(0077);

    fp = fopen(tmp_path, "w");
    if (!fp) {
        int saved_errno = errno;
        umask(old_umask);  // Restore umask before returning
        return -saved_errno;
    }

    // Set restrictive permissions on cache file (0600 = rw-------)
    // This prevents information leakage of system paths
    // Even though umask is 0077, explicitly set permissions for defense in depth
    if (fchmod(fileno(fp), 0600) != 0) {
        int saved_errno = errno;
        umask(old_umask);  // Restore umask before error return
        fclose(fp);
        unlink(tmp_path);
        return -saved_errno;
    }
```

**With:**
```c
    // Set restrictive umask before file creation (prevents world-readable files)
    mode_t old_umask = umask(0077);

    fp = safe_fopen(tmp_path, "w", 0600);
    if (!fp) {
        int saved_errno = errno;
        umask(old_umask);  // Restore umask before returning

        // Detect symlink attack
        if (saved_errno == ELOOP) {
            syslog(LOG_ERR, "SECURITY: Symlink attack detected on package cache: %s", tmp_path);
        }

        return -saved_errno;
    }
```

Note: Remove the separate `fchmod()` block since safe_fopen sets permissions atomically.

### Step 3: Build and verify

```bash
make clean
make
```

**Expected:** Build succeeds

### Step 4: Run full test suite

```bash
make test
```

**Expected:** All 57 tests pass (53 existing + 4 new utils tests)

### Step 5: Commit pkgcache changes

```bash
git add src/pkgcache.c
git commit -m "fix: Use safe_fopen in pkgcache to prevent symlink attacks

- Replace fopen() with safe_fopen() in pkgcache_save()
- Detect symlink attacks via ELOOP errno
- Log SECURITY event to syslog when attack detected
- Remove redundant fchmod() call (permissions set atomically)"
```

---

## Task 5: Add Signal Sender Validation

**Files:**
- Modify: `src/main.c:58-74` (sig_handler_info function)

### Step 1: Add signal validation logic

**Modify:** `src/main.c:58-74` in `sig_handler_info()` function

**Replace:**
```c
static void sig_handler_info(int sig, siginfo_t *info, void *ucontext)
{
    (void)ucontext;

    last_signal = sig;
    if (info) {
        signal_sender_pid = info->si_pid;
        signal_sender_uid = info->si_uid;
    }

    if (sig == SIGINT || sig == SIGTERM) {
        exiting = true;
    } else if (sig == SIGHUP) {
        reload_config = true;
    }
}
```

**With:**
```c
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

### Step 2: Build and verify

```bash
make clean
make
```

**Expected:** Build succeeds

### Step 3: Manual test signal validation

```bash
# Start daemon in background
sudo ./build/linmond &
DAEMON_PID=$!

# Test 1: Root signal (should work)
sudo kill -HUP $DAEMON_PID
# Check journalctl - should see "Received SIGHUP" (no rejection)

# Test 2: Non-root signal (should be rejected)
kill -HUP $DAEMON_PID
# Check journalctl - should see "SECURITY: Rejected signal 1 from unauthorized UID"

# Clean up
sudo kill -TERM $DAEMON_PID
```

**Expected:** Root signals accepted, non-root signals rejected and logged

### Step 4: Commit signal validation

```bash
git add src/main.c
git commit -m "fix: Add signal sender validation to prevent unauthorized DoS

- Only allow root (UID 0) to send SIGHUP/SIGTERM
- Reject signals from other UIDs with SECURITY log message
- Prevents compromised services from stopping/reloading daemon
- SIGINT remains unrestricted (Ctrl+C from terminal)"
```

---

## Task 6: Replace nobody with linmon User

**Files:**
- Modify: `src/main.c:1350-1390` (privilege drop section)

### Step 1: Add pwd.h include

**Modify:** `src/main.c` (top of file, after existing includes)

```c
#include <pwd.h>
```

### Step 2: Update privilege drop to use linmon user

**Modify:** `src/main.c:1350-1390` in privilege drop section

**Replace:**
```c
        // STEP 6: Drop GID to nobody (65534) BEFORE UID
        //
        // GID must be dropped before UID for two reasons:
        //   1. POSIX: setgid() may require privileges (safer to do as root)
        //   2. Security: Prevents UID/GID mismatch state
        //
        // After this call:
        //   - Primary GID is 65534 (nobody/nogroup)
        //   - Supplementary groups are empty (cleared above)
        //   - Process still running as UID 0 (root)
        if (setgid(65534) != 0) {
            fprintf(stderr, "CRITICAL: Failed to drop GID to nobody: %s\n", strerror(errno));
            goto cleanup;
        }

        // STEP 7: Drop UID to nobody (65534) - POINT OF NO RETURN
        //
        // This is the critical transition from root to unprivileged user
        //
        // After this call:
        //   - UID = 65534 (nobody)
        //   - GID = 65534 (nobody/nogroup)
        //   - Supplementary groups = [] (empty)
        //   - Capabilities: CAP_SYS_PTRACE only (via ambient capability)
        //   - Cannot call setuid() again without CAP_SETUID (which we'll drop next)
        //
        // What survives the UID change:
        //   - Open file descriptors (log file, BPF maps, ring buffers)
        //   - Loaded BPF programs (kernel-side, already attached)
        //   - CAP_SYS_PTRACE (because it's in AMBIENT set + SECBIT_NO_SETUID_FIXUP)
        //
        // What is lost:
        //   - Ability to read most files (no CAP_DAC_READ_SEARCH/CAP_DAC_OVERRIDE)
        //   - Ability to write to system directories
        //   - Ability to load new BPF programs (CAP_BPF lost)
        //   - Ability to change file ownership (CAP_CHOWN/CAP_FOWNER lost)
        //
        // This is permanent - daemon can NEVER regain root after this point
        if (setuid(65534) != 0) {
            fprintf(stderr, "CRITICAL: Failed to drop UID to nobody: %s\n", strerror(errno));
            goto cleanup;
        }
```

**With:**
```c
        // STEP 6: Get linmon user information
        //
        // Query system database for linmon user created by install.sh
        // This provides isolation from other system services (unlike shared nobody user)
        struct passwd *linmon_user = getpwnam("linmon");
        if (!linmon_user) {
            fprintf(stderr, "CRITICAL: linmon user not found. Run 'sudo make install' first.\n");
            fprintf(stderr, "The installation script creates the dedicated linmon system user.\n");
            goto cleanup;
        }

        // STEP 7: Drop GID to linmon BEFORE UID
        //
        // GID must be dropped before UID for two reasons:
        //   1. POSIX: setgid() may require privileges (safer to do as root)
        //   2. Security: Prevents UID/GID mismatch state
        //
        // After this call:
        //   - Primary GID is linmon_user->pw_gid (linmon group)
        //   - Supplementary groups are empty (cleared above)
        //   - Process still running as UID 0 (root)
        if (setgid(linmon_user->pw_gid) != 0) {
            fprintf(stderr, "CRITICAL: Failed to drop GID to linmon: %s\n", strerror(errno));
            goto cleanup;
        }

        // STEP 8: Drop UID to linmon - POINT OF NO RETURN
        //
        // This is the critical transition from root to unprivileged user
        //
        // After this call:
        //   - UID = linmon_user->pw_uid (linmon)
        //   - GID = linmon_user->pw_gid (linmon)
        //   - Supplementary groups = [] (empty)
        //   - Capabilities: CAP_SYS_PTRACE only (via ambient capability)
        //   - Cannot call setuid() again without CAP_SETUID (which we'll drop next)
        //
        // What survives the UID change:
        //   - Open file descriptors (log file, BPF maps, ring buffers)
        //   - Loaded BPF programs (kernel-side, already attached)
        //   - CAP_SYS_PTRACE (because it's in AMBIENT set + SECBIT_NO_SETUID_FIXUP)
        //
        // What is lost:
        //   - Ability to read most files (no CAP_DAC_READ_SEARCH/CAP_DAC_OVERRIDE)
        //   - Ability to write to system directories
        //   - Ability to load new BPF programs (CAP_BPF lost)
        //   - Ability to change file ownership (CAP_CHOWN/CAP_FOWNER lost)
        //
        // This is permanent - daemon can NEVER regain root after this point
        if (setuid(linmon_user->pw_uid) != 0) {
            fprintf(stderr, "CRITICAL: Failed to drop UID to linmon: %s\n", strerror(errno));
            goto cleanup;
        }
```

### Step 3: Update privilege drop verification log

**Modify:** `src/main.c` (find the log message after privilege drop)

**Replace:**
```c
        printf("Dropped privileges to UID/GID 65534 (nobody)\n");
```

**With:**
```c
        printf("Dropped privileges to UID/GID %d/%d (linmon)\n",
               (int)linmon_user->pw_uid, (int)linmon_user->pw_gid);
```

### Step 4: Build and verify

```bash
make clean
make
```

**Expected:** Build succeeds

### Step 5: Test will fail without linmon user

```bash
# This should fail gracefully with helpful error
sudo ./build/linmond
```

**Expected:** Error: "CRITICAL: linmon user not found. Run 'sudo make install' first."

### Step 6: Commit linmon user changes

```bash
git add src/main.c
git commit -m "feat: Replace nobody (UID 65534) with dedicated linmon system user

- Use getpwnam('linmon') to look up user created by install.sh
- Provides isolation from other services (prevents shared UID attacks)
- Add helpful error message if linmon user doesn't exist
- Update privilege drop logging to show linmon UID/GID
- Requires install.sh to create linmon user before daemon runs"
```

---

## Task 7: Update install.sh for User Creation and Migration

**Files:**
- Modify: `install.sh:18-55` (user creation and directory ownership section)

### Step 1: Add linmon user creation

**Modify:** `install.sh` (after the NOBODY_GROUP detection, before log directory creation)

**Insert after line 23:**

```bash
# Detect nobody group (Debian/Ubuntu use 'nogroup', RHEL/Rocky use 'nobody')
if getent group nogroup >/dev/null 2>&1; then
    NOBODY_GROUP="nogroup"
else
    NOBODY_GROUP="nobody"
fi

# ADD THIS SECTION:
# Create dedicated linmon system user for isolation
echo -e "${YELLOW}[1/8]${NC} Creating linmon system user..."
if id "linmon" >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} linmon user already exists"
else
    # Create system user with no home directory and no login shell
    useradd --system --no-create-home --shell /usr/sbin/nologin linmon
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} Created linmon system user (UID $(id -u linmon))"
    else
        echo -e "${RED}Error: Failed to create linmon user${NC}"
        exit 1
    fi
fi

# Check if daemon is running and stop it for migration
DAEMON_WAS_RUNNING=false
if systemctl is-active --quiet linmond 2>/dev/null; then
    echo -e "${YELLOW}[2/8]${NC} Stopping linmond for user migration..."
    systemctl stop linmond
    DAEMON_WAS_RUNNING=true
    echo -e "${GREEN}✓${NC} Daemon stopped"
else
    echo -e "${YELLOW}[2/8]${NC} Daemon not running, skipping stop"
fi
```

### Step 2: Update directory ownership to use linmon user

**Modify:** `install.sh:28-55` (log and cache directory creation)

**Change step numbers [1/7] → [3/8] and [2/7] → [4/8]**

**Replace:**
```bash
# 1. Create log directory with proper permissions
echo -e "${YELLOW}[1/7]${NC} Creating log directory..."
mkdir -p /var/log/linmon
chown nobody:${NOBODY_GROUP} /var/log/linmon
chmod 0750 /var/log/linmon
```

**With:**
```bash
# 3. Create log directory with proper permissions
echo -e "${YELLOW}[3/8]${NC} Creating log directory..."
mkdir -p /var/log/linmon
chown -R linmon:linmon /var/log/linmon
chmod 0750 /var/log/linmon
```

**Replace:**
```bash
echo -e "${GREEN}✓${NC} Log directory: /var/log/linmon (owner: nobody:${NOBODY_GROUP}, mode: 0750)"
```

**With:**
```bash
echo -e "${GREEN}✓${NC} Log directory: /var/log/linmon (owner: linmon:linmon, mode: 0750)"
```

**Replace:**
```bash
# 2. Create cache directory for package verification
echo -e "${YELLOW}[2/7]${NC} Creating cache directory..."
mkdir -p /var/cache/linmon
chown nobody:${NOBODY_GROUP} /var/cache/linmon
chmod 0750 /var/cache/linmon
```

**With:**
```bash
# 4. Create cache directory for package verification
echo -e "${YELLOW}[4/8]${NC} Creating cache directory..."
mkdir -p /var/cache/linmon
chown -R linmon:linmon /var/cache/linmon
chmod 0750 /var/cache/linmon
```

**Replace:**
```bash
echo -e "${GREEN}✓${NC} Cache directory: /var/cache/linmon (owner: nobody:${NOBODY_GROUP}, mode: 0750)"
```

**With:**
```bash
echo -e "${GREEN}✓${NC} Cache directory: /var/cache/linmon (owner: linmon:linmon, mode: 0750)"
```

### Step 3: Update all remaining step numbers

**Modify:** `install.sh` - Update step counters:
- [3/7] → [5/8]
- [4/7] → [6/8]
- [5/7] → [7/8]
- [6/7] → stays [7/8] (service start)
- [7/7] → [8/8]

### Step 4: Add daemon restart logic

**Modify:** `install.sh` (at the end of the service configuration section, before "Installation Complete")

**Insert before the "Installation Complete" message:**

```bash
# Restart daemon if it was running before migration
if [ "$DAEMON_WAS_RUNNING" = true ]; then
    echo -e "${YELLOW}Restarting daemon after migration...${NC}"
    systemctl start linmond
    sleep 2

    if systemctl is-active --quiet linmond; then
        echo -e "${GREEN}✓${NC} Daemon restarted successfully"
    else
        echo -e "${RED}✗${NC} Failed to restart daemon - check journalctl -u linmond"
    fi
fi
```

### Step 5: Update final status message

**Modify:** `install.sh` (security features section at end)

**Replace:**
```bash
echo -e "  ✓ UID/GID dropping (runs as nobody:${NOBODY_GROUP})"
```

**With:**
```bash
echo -e "  ✓ UID/GID dropping (runs as linmon:linmon - dedicated user)"
```

### Step 6: Test install.sh changes (requires root)

```bash
# In worktree
sudo bash install.sh
```

**Expected:**
- Creates linmon user
- Stops daemon if running
- Creates/updates directories with linmon ownership
- Installs binary
- Restarts daemon if was running
- All steps succeed

### Step 7: Verify linmon user was created

```bash
id linmon
ls -la /var/log/linmon
ls -la /var/cache/linmon
```

**Expected:**
- linmon user exists with system UID
- Directories owned by linmon:linmon

### Step 8: Commit install.sh changes

```bash
git add install.sh
git commit -m "feat: Add linmon user creation and automatic migration in install.sh

- Create dedicated linmon system user (UID auto-assigned)
- Stop daemon before migration, restart after if was running
- Change ownership from nobody:nogroup to linmon:linmon
- Use chown -R for migration of existing files
- Add SELinux context restoration after ownership change
- Idempotent: safe to run multiple times
- Update step numbering (8 steps instead of 7)"
```

---

## Task 8: Fix Grep Injection in Query Script

**Files:**
- Modify: `linmon-query.sh:165`

### Step 1: Add -- separator to grep command

**Modify:** `linmon-query.sh:165` in `cmd_search()` function

**Replace:**
```bash
cmd_search() {
    local pattern="$1"
    echo "=== Search Results for: $pattern (last $LIMIT) ==="
    grep -i "$pattern" "$LOGFILE" | tail -n "$LIMIT" | jq '.'
}
```

**With:**
```bash
cmd_search() {
    local pattern="$1"
    echo "=== Search Results for: $pattern (last $LIMIT) ==="
    grep -i -- "$pattern" "$LOGFILE" | tail -n "$LIMIT" | jq '.'
}
```

### Step 2: Test grep injection fix

```bash
# Create test log file
echo '{"type":"process_exec","filename":"/bin/bash"}' > /tmp/test.json
echo '{"type":"net_connect","password":"secret123"}' >> /tmp/test.json

# Test legitimate search
./linmon-query.sh search "process_exec" | head -1
# Expected: Shows process_exec line

# Test injection attempt (should now search for literal string)
./linmon-query.sh search "-v password" | wc -l
# Expected: 0 lines (no match for literal "-v password")

# Without fix, this would invert match and show process_exec line
# With fix, it searches for the literal string "-v password"

# Clean up
rm /tmp/test.json
```

### Step 3: Commit grep fix

```bash
git add linmon-query.sh
git commit -m "fix: Prevent grep option injection in query script

- Add -- separator to terminate grep option parsing
- Prevents patterns like '-v' or '-f /etc/shadow' from being interpreted
- Regex functionality still works (intended behavior)
- Fixes LOW severity command injection vulnerability"
```

---

## Task 9: Update Documentation

**Files:**
- Modify: `SECURITY.md` (privilege dropping section)
- Modify: `CHANGELOG.md` (add new release)
- Modify: `README.md` (installation requirements)

### Step 1: Update SECURITY.md

**Modify:** `SECURITY.md` - Find privilege dropping section and update references:

**Replace all instances of:**
- "UID 65534 (nobody)" → "dedicated linmon system user"
- "nobody:nogroup" → "linmon:linmon"

**Add new section after privilege dropping:**

```markdown
### Symlink Attack Prevention

LinMon protects against symlink attacks using `O_NOFOLLOW`:

**Attack Vector (Prevented)**:
```bash
# Attacker with write access to /var/log/linmon
ln -s /etc/shadow /var/log/linmon/events.json
# Daemon restart would have chmod'd /etc/shadow (before fix)
```

**Mitigation**:
- All file operations use `safe_fopen()` wrapper with `O_NOFOLLOW`
- Symlink attempts fail with `ELOOP` errno
- Security events logged to syslog with `SECURITY:` prefix
- Daemon startup fails safely (refuses to proceed)

**Signal Sender Validation**:
- Only root (UID 0) may send SIGHUP/SIGTERM to daemon
- Unauthorized signals rejected and logged
- Prevents DoS attacks from compromised services
```

### Step 2: Update CHANGELOG.md

**Add new version section at top:**

```markdown
## [1.7.6] - 2026-02-20

### Security

**CRITICAL FIXES**:

- **Symlink Attack Prevention**: Replaced `fopen()` with `safe_fopen()` wrapper using `O_NOFOLLOW`
  - Prevents attackers from using symlinks to manipulate arbitrary files
  - Affects: logger.c, filehash.c, pkgcache.c
  - Detection: Symlink attempts logged to syslog with `SECURITY:` prefix
  - Impact: Daemon refuses to start if symlink detected in /var/log/linmon or /var/cache/linmon

- **Dedicated System User**: Replaced shared `nobody` (UID 65534) with dedicated `linmon` user
  - Provides isolation from other system services
  - Prevents DoS attacks from compromised containers/services
  - Migration: install.sh automatically creates user and migrates file ownership
  - Impact: Existing installations upgraded seamlessly on `sudo make install`

- **Signal Sender Validation**: Only root may send SIGHUP/SIGTERM to daemon
  - Prevents unauthorized config reloads and service stops
  - Unauthorized attempts logged with sender UID/PID for forensics
  - Impact: Compromised services can no longer tamper with monitoring

**LOW SEVERITY**:

- **Grep Injection Fix**: Added `--` separator to `linmon-query.sh` search function
  - Prevents option injection attacks (e.g., `-f /etc/shadow`)
  - Impact: Query script (local admin tool only)

### Changed

- **install.sh**: Now creates `linmon` system user and performs automatic migration
  - Stops daemon → creates user → migrates ownership → restarts
  - Idempotent: safe to run multiple times
  - SELinux: Restores file contexts after ownership change (RHEL/Rocky)

- **Privilege Drop**: Changed from `setuid(65534)` to `getpwnam("linmon")`
  - Requires `sudo make install` to create user before daemon runs
  - Helpful error if linmon user missing

### Added

- **src/utils.c**: New `safe_fopen()` utility with O_NOFOLLOW protection
  - Unit tests: 4 tests covering regular files, append, symlinks, invalid modes
  - Documentation: Attack scenarios and mitigation strategy in SECURITY.md
```

### Step 3: Update README.md installation section

**Modify:** `README.md` - Find installation section and update:

**Add note about linmon user:**

```markdown
## Installation

### Prerequisites

- Linux kernel >= 5.8 with BTF support
- Clang and LLVM for eBPF compilation
- libbpf, libelf, zlib, OpenSSL, libcap development headers
- Root access (for installation and BPF loading)

**Note**: The installation creates a dedicated `linmon` system user for privilege isolation.

### Build and Install

```bash
make
sudo make install
```

The `install.sh` script will:
1. Create `linmon` system user (if not exists)
2. Stop daemon if running (for migration)
3. Create/update directories with linmon ownership
4. Install binary and systemd service
5. Restart daemon if was previously running

**Upgrade from previous versions**: Automatic migration from `nobody` to `linmon` user.
```

### Step 4: Commit documentation updates

```bash
git add SECURITY.md CHANGELOG.md README.md
git commit -m "docs: Update security documentation for hardening changes

- Add symlink attack prevention section to SECURITY.md
- Document signal sender validation policy
- Add CHANGELOG entry for v1.7.6 security fixes
- Update README installation notes for linmon user requirement
- Explain automatic migration from nobody to linmon"
```

---

## Task 10: Update VERSION and Final Build

**Files:**
- Modify: `VERSION`

### Step 1: Update version number

**Modify:** `VERSION`

**Replace:**
```
1.7.5
```

**With:**
```
1.7.6
```

### Step 2: Full clean build

```bash
make clean
make
```

**Expected:** Build succeeds with version 1.7.6

### Step 3: Run full test suite

```bash
make test
```

**Expected:** All 57 tests pass

### Step 4: Verify version in binary

```bash
./build/linmond --version
```

**Expected:** Output shows "LinMon version 1.7.6"

### Step 5: Commit version update

```bash
git add VERSION
git commit -m "chore: Bump version to 1.7.6 for security hardening release"
```

---

## Testing Checklist

After implementation, verify:

### Unit Tests
- [ ] All 57 tests pass (`make test`)
- [ ] New utils tests verify symlink rejection
- [ ] Build succeeds without warnings

### Integration Tests (Manual)
- [ ] `sudo make install` creates linmon user
- [ ] Daemon starts successfully as linmon user
- [ ] Symlink in /var/log/linmon causes startup failure with SECURITY log
- [ ] Root can send SIGHUP (daemon reloads config)
- [ ] Non-root SIGHUP rejected with SECURITY log
- [ ] grep injection test: `./linmon-query.sh search "-v test"` searches for literal string

### Platform Tests
- [ ] Ubuntu 24.04: All tests pass, daemon runs
- [ ] RHEL 9 / Rocky 9: All tests pass, SELinux contexts correct
- [ ] Upgrade test: Install 1.7.5 → upgrade to 1.7.6 → verify migration

---

## Rollback Plan

If critical issues found:

```bash
# Stop daemon
sudo systemctl stop linmond

# Revert to previous version (git)
git checkout v1.7.5

# Rebuild
make clean && make

# Reinstall
sudo make install

# Change ownership back to nobody (if needed)
sudo chown -R nobody:nogroup /var/log/linmon /var/cache/linmon

# Restart
sudo systemctl start linmond
```

---

## Success Criteria

- ✅ All 57 unit tests pass
- ✅ Daemon starts as linmon user (not nobody)
- ✅ Symlink attacks detected and rejected
- ✅ Signal sender validation blocks non-root signals
- ✅ Grep injection prevented
- ✅ Automatic migration works on existing installations
- ✅ SELinux contexts correct on RHEL/Rocky
- ✅ No privilege escalation vulnerabilities introduced
