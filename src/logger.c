// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// Event logging implementation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <limits.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>

#include "logger.h"
#include "userdb.h"
#include "filehash.h"
#include "pkgcache.h"
#include "procfs.h"
#include "containerinfo.h"

static FILE *log_fp = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool enable_resolve_usernames = false;
static bool enable_hash_binaries = false;
static bool enable_verify_packages = false;
static bool enable_container_metadata = false;  // Resolve container IDs from cgroups
static bool enable_syslog = false;  // Log all events to syslog (in addition to JSON)
static unsigned long write_error_count = 0;
static bool log_write_errors = true;  // Only log first few errors to avoid spam
static char hostname[256] = {0};  // Cached hostname for multi-host SIEM deployments

// Tamper detection - sequence numbers
static uint64_t event_sequence = 0;  // Monotonic counter for all events
static unsigned long event_count = 0;  // Total events logged
static pthread_mutex_t seq_mutex = PTHREAD_MUTEX_INITIALIZER;

// Log rotation settings
static bool rotation_enabled = false;
static char rotation_base_path[512] = {0};
static unsigned long rotation_max_size = 100 * 1024 * 1024;  // 100MB default
static int rotation_max_files = 10;
static unsigned long bytes_written = 0;
static const unsigned long ROTATION_CHECK_INTERVAL = 4096;  // Check every 4KB written

int logger_init(const char *log_file)
{
    // Set restrictive umask for log file creation (prevents world-readable files)
    mode_t old_umask = umask(0077);

    log_fp = fopen(log_file, "a");
    if (!log_fp) {
        int saved_errno = errno;
        umask(old_umask);  // Restore umask before returning
        return -saved_errno;
    }

    // Set permissions to 0640 (rw-r-----) for defense in depth
    // Even though directory is 0750, file should also have restrictive permissions
    chmod(log_file, 0640);

    // Restore original umask (don't affect other operations)
    umask(old_umask);

    // Set line buffering
    setlinebuf(log_fp);

    // Get hostname for multi-host SIEM deployments
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        // Fallback to "unknown" if gethostname fails
        strncpy(hostname, "unknown", sizeof(hostname) - 1);
        hostname[sizeof(hostname) - 1] = '\0';
    } else {
        // Ensure null termination (POSIX doesn't guarantee it)
        hostname[sizeof(hostname) - 1] = '\0';
    }

    return 0;
}

void logger_set_enrichment(bool resolve_usernames, bool hash_binaries,
                           bool verify_packages, bool container_metadata)
{
    enable_resolve_usernames = resolve_usernames;
    enable_hash_binaries = hash_binaries;
    enable_verify_packages = verify_packages;
    enable_container_metadata = container_metadata;
}

void logger_set_rotation(const char *log_file, bool enabled,
                         unsigned long max_size, int max_files)
{
    rotation_enabled = enabled;
    if (log_file && strlen(log_file) < sizeof(rotation_base_path)) {
        strncpy(rotation_base_path, log_file, sizeof(rotation_base_path) - 1);
        rotation_base_path[sizeof(rotation_base_path) - 1] = '\0';
    }
    rotation_max_size = max_size;
    rotation_max_files = max_files;
    bytes_written = 0;
}

void logger_set_syslog(bool enabled)
{
    enable_syslog = enabled;
}

// Helper: Convert container runtime enum to string (for syslog)
static const char *container_runtime_name(const struct container_info *info)
{
    switch (info->runtime) {
    case RUNTIME_DOCKER:
        return "docker";
    case RUNTIME_PODMAN:
        return "podman";
    case RUNTIME_CONTAINERD:
        return "containerd";
    case RUNTIME_LXC:
        return "lxc";
    case RUNTIME_SYSTEMD_NSPAWN:
        return "systemd-nspawn";
    case RUNTIME_KUBERNETES:
        return "kubernetes";
    case RUNTIME_UNKNOWN:
        return "unknown";
    case RUNTIME_NONE:
    default:
        return "none";
    }
}

// Helper: Safe append to syslog buffer with overflow protection
// Returns true if append succeeded, false if buffer full
// SECURITY: Prevents buffer overflow from snprintf() return value accumulation
static bool syslog_append(char *buf, size_t bufsize, size_t *pos, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static bool syslog_append(char *buf, size_t bufsize, size_t *pos, const char *fmt, ...)
{
    // Safety check: if position already at/past end, buffer is full
    if (*pos >= bufsize - 1) {
        return false;  // Buffer full, cannot append
    }

    va_list args;
    va_start(args, fmt);

    // Calculate remaining space (always leave room for NULL terminator)
    size_t remaining = bufsize - *pos;

    // vsnprintf to format string into remaining buffer space
    int written = vsnprintf(buf + *pos, remaining, fmt, args);
    va_end(args);

    // Check for errors or truncation
    if (written < 0) {
        return false;  // Encoding error
    }

    // snprintf returns bytes that WOULD be written (can exceed buffer)
    // Only advance position by actual bytes written (capped at remaining-1)
    if ((size_t)written >= remaining) {
        // Output was truncated - advance to end of buffer
        *pos = bufsize - 1;
        buf[*pos] = '\0';  // Ensure NULL termination
        return false;  // Indicate truncation
    }

    // Success: advance position by actual written bytes
    *pos += written;
    return true;
}

// Perform log rotation: events.json -> events.json.1 -> events.json.2 -> ...
// Must be called with log_mutex held
static void rotate_log_file(void)
{
    char old_path[600];
    char new_path[600];
    FILE *new_fp;

    if (!rotation_enabled || rotation_base_path[0] == '\0')
        return;

    // Close current file
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }

    // Rotate existing files: .9 -> .10, .8 -> .9, ..., .1 -> .2
    for (int i = rotation_max_files - 1; i >= 1; i--) {
        snprintf(old_path, sizeof(old_path), "%s.%d", rotation_base_path, i);
        snprintf(new_path, sizeof(new_path), "%s.%d", rotation_base_path, i + 1);

        // Delete oldest if it exists and we're at max
        if (i == rotation_max_files - 1) {
            unlink(new_path);  // Ignore error if doesn't exist
        }

        // Rename .N to .N+1
        rename(old_path, new_path);  // Ignore error if doesn't exist
    }

    // Rename current to .1
    snprintf(new_path, sizeof(new_path), "%s.1", rotation_base_path);
    rename(rotation_base_path, new_path);

    // Open fresh log file with restrictive permissions
    mode_t old_umask = umask(0077);
    new_fp = fopen(rotation_base_path, "a");
    if (new_fp) {
        chmod(rotation_base_path, 0640);  // Set restrictive permissions
        umask(old_umask);
        setlinebuf(new_fp);
        log_fp = new_fp;
        bytes_written = 0;
        fprintf(stderr, "Log rotated: %s\n", rotation_base_path);
    } else {
        umask(old_umask);
        fprintf(stderr, "ERROR: Failed to reopen log after rotation: %s\n",
                strerror(errno));
    }
}

// Check if rotation is needed and perform it
// Must be called with log_mutex held
static void check_rotation(void)
{
    struct stat st;

    if (!rotation_enabled || rotation_base_path[0] == '\0')
        return;

    // Only check file size periodically to reduce stat() calls
    if (bytes_written < ROTATION_CHECK_INTERVAL)
        return;

    bytes_written = 0;  // Reset counter

    // Get actual file size
    if (log_fp && fstat(fileno(log_fp), &st) == 0) {
        if ((unsigned long)st.st_size >= rotation_max_size) {
            rotate_log_file();
        }
    }
}

void logger_replace(FILE *new_fp)
{
    FILE *old_fp;

    if (!new_fp)
        return;

    // Atomically swap file pointer while holding mutex
    // This ensures no logger_log_*() call sees NULL log_fp
    pthread_mutex_lock(&log_mutex);
    old_fp = log_fp;
    log_fp = new_fp;
    // Reset error counter on log file rotation
    write_error_count = 0;
    log_write_errors = true;
    pthread_mutex_unlock(&log_mutex);

    // Close old file outside mutex to avoid blocking logging
    if (old_fp)
        fclose(old_fp);
}

// Check fprintf result, track bytes written, and trigger rotation if needed
// Must be called with log_mutex held
static inline bool check_fprintf_result(int ret)
{
    if (ret < 0) {
        write_error_count++;
        // Only log first 10 errors to avoid stderr spam
        if (log_write_errors && write_error_count <= 10) {
            fprintf(stderr, "Warning: Failed to write to log file (error count: %lu)\n",
                    write_error_count);
            if (write_error_count == 10) {
                fprintf(stderr, "Warning: Suppressing further log write errors\n");
                log_write_errors = false;
            }
        }
        return false;
    }

    // Track bytes written for rotation check
    if (ret > 0) {
        bytes_written += ret;
        // Check if rotation is needed
        check_rotation();
    }

    return true;
}

// Check if comm name mismatches process_name (masquerading detection)
// Handles TASK_COMM_LEN truncation (max 15 chars) intelligently
// Returns true if mismatch detected (potential masquerading)
static bool is_comm_mismatch(const char *comm, const char *process_name)
{
    if (!comm || !process_name)
        return false;

    size_t name_len = strlen(process_name);

    // If process_name is longer than 15 chars (TASK_COMM_LEN - 1),
    // comm will be truncated, so compare only the first 15 chars
    if (name_len > 15) {
        return (strncmp(comm, process_name, 15) != 0);
    }

    // process_name fits in comm, do full comparison
    return (strcmp(comm, process_name) != 0);
}

// Read executable path from /proc/<pid>/exe symlink and extract process_name (basename)
// Uses readlink() which works without CAP_SYS_PTRACE (only needs symlink read permission)
// Returns true if successful, false otherwise
// Sets process_name_out to basename of executable path
// Optionally detects if executable is deleted (is_deleted can be NULL)
static bool get_process_name_from_proc(pid_t pid, char *process_name_out, size_t size, bool *is_deleted)
{
    char proc_path[64];
    char exe_path[PATH_MAX];
    ssize_t len;

    if (!process_name_out || size == 0)
        return false;

    process_name_out[0] = '\0';
    if (is_deleted)
        *is_deleted = false;

    // Read /proc/<pid>/exe symlink
    // readlink() works without CAP_SYS_PTRACE - only needs symlink read permission
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
    len = readlink(proc_path, exe_path, sizeof(exe_path) - 1);
    if (len == -1) {
        return false;  // Process may have exited or no permission
    }

    exe_path[len] = '\0';  // readlink() doesn't null-terminate

    // Check for deleted executable marker " (deleted)"
    if (is_deleted) {
        *is_deleted = (strstr(exe_path, " (deleted)") != NULL);
    }

    // Extract basename from path (strip " (deleted)" suffix if present)
    char *basename = strrchr(exe_path, '/');
    if (basename) {
        basename++;  // Skip the '/'
    } else {
        basename = exe_path;  // No slash, use full path
    }

    // Strip " (deleted)" suffix from basename if present
    char *deleted_marker = strstr(basename, " (deleted)");
    if (deleted_marker) {
        *deleted_marker = '\0';  // Truncate at marker
    }

    // Copy to output
    strncpy(process_name_out, basename, size - 1);
    process_name_out[size - 1] = '\0';
    return (process_name_out[0] != '\0');
}

// Escape special characters for JSON strings
static void json_escape(const char *src, char *dst, size_t dst_size)
{
    size_t j = 0;

    if (!src || !dst || dst_size == 0)
        return;

    for (size_t i = 0; src[i] && j < dst_size - 1; i++) {
        unsigned char c = src[i];

        // Check if we have room for escape sequence
        if (j >= dst_size - 6)
            break;

        switch (c) {
        case '"':
            dst[j++] = '\\';
            dst[j++] = '"';
            break;
        case '\\':
            dst[j++] = '\\';
            dst[j++] = '\\';
            break;
        case '\b':
            dst[j++] = '\\';
            dst[j++] = 'b';
            break;
        case '\f':
            dst[j++] = '\\';
            dst[j++] = 'f';
            break;
        case '\n':
            dst[j++] = '\\';
            dst[j++] = 'n';
            break;
        case '\r':
            dst[j++] = '\\';
            dst[j++] = 'r';
            break;
        case '\t':
            dst[j++] = '\\';
            dst[j++] = 't';
            break;
        default:
            // Control characters - escape as \uXXXX
            if (c < 0x20) {
                // Ensure we have room for full escape sequence
                if (j + 6 >= dst_size)
                    break;
                int written = snprintf(dst + j, dst_size - j, "\\u%04x", c);
                if (written > 0 && written < (int)(dst_size - j))
                    j += written;
                else
                    break;  // snprintf failed or would truncate
            } else {
                dst[j++] = c;
            }
            break;
        }
    }
    dst[j] = '\0';
}

static void format_timestamp(char *buf, size_t size)
{
    struct timespec ts;
    struct tm tm_info;
    size_t len;

    if (size == 0)
        return;

    // Get current wall-clock time
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm_info);

    // Format with millisecond precision
    // Format: YYYY-MM-DDTHH:MM:SS.mmmZ (25 chars + null = 26)
    len = strftime(buf, size, "%Y-%m-%dT%H:%M:%S", &tm_info);
    if (len > 0 && len + 5 < size) {  // Ensure room for ".mmmZ\0"
        snprintf(buf + len, size - len, ".%03ldZ", ts.tv_nsec / 1000000);
    } else if (len > 0) {
        // Not enough room for milliseconds, just add Z
        buf[len] = 'Z';
        buf[len + 1] = '\0';
    }
}

// Log container information (sparse field - only if in container)
// Must be called with log_mutex held
static void log_container_info(pid_t pid, uint32_t pid_ns, uint32_t mnt_ns, uint32_t net_ns)
{
    int ret;

    if (!enable_container_metadata)
        return;

    // Check if process is in container (namespace differs from init)
    if (!containerinfo_is_in_container(pid_ns, mnt_ns, net_ns))
        return;  // Host process - no container field

    // Get container metadata from cgroups
    struct container_info info;
    if (!containerinfo_get(pid, &info))
        return;  // Could not get container info (process may have exited)

    // Log container field (sparse - only if in container)
    ret = fprintf(log_fp, ",\"container\":{");
    if (!check_fprintf_result(ret))
        return;  // Write failed, abort

    // Container runtime
    const char *runtime_str = "unknown";
    switch (info.runtime) {
    case RUNTIME_DOCKER:
        runtime_str = "docker";
        break;
    case RUNTIME_PODMAN:
        runtime_str = "podman";
        break;
    case RUNTIME_CONTAINERD:
        runtime_str = "containerd";
        break;
    case RUNTIME_LXC:
        runtime_str = "lxc";
        break;
    case RUNTIME_SYSTEMD_NSPAWN:
        runtime_str = "systemd-nspawn";
        break;
    case RUNTIME_KUBERNETES:
        runtime_str = "kubernetes";
        break;
    default:
        runtime_str = "unknown";
    }

    ret = fprintf(log_fp, "\"runtime\":\"%s\"", runtime_str);
    if (!check_fprintf_result(ret))
        goto close_json;  // Write failed, try to close JSON object

    // Container ID (if available)
    if (info.id[0]) {
        char id_escaped[CONTAINER_ID_LEN * 6];
        json_escape(info.id, id_escaped, sizeof(id_escaped));
        ret = fprintf(log_fp, ",\"id\":\"%s\"", id_escaped);
        if (!check_fprintf_result(ret))
            goto close_json;
    }

    // Pod ID (for Kubernetes)
    if (info.pod_id[0]) {
        char pod_escaped[CONTAINER_ID_LEN * 6];
        json_escape(info.pod_id, pod_escaped, sizeof(pod_escaped));
        ret = fprintf(log_fp, ",\"pod_id\":\"%s\"", pod_escaped);
        if (!check_fprintf_result(ret))
            goto close_json;
    }

    // Namespace inodes (for correlation)
    ret = fprintf(log_fp, ",\"ns_pid\":%u,\"ns_mnt\":%u,\"ns_net\":%u",
            pid_ns, mnt_ns, net_ns);
    check_fprintf_result(ret);  // Check but don't abort, we're almost done

close_json:
    fprintf(log_fp, "}");  // Always try to close JSON object
}

int logger_log_process_event(const struct process_event *event)
{
    char timestamp[64];
    char hostname_escaped[256 * 6];
    char comm_escaped[TASK_COMM_LEN * 6];
    char filename_escaped[MAX_FILENAME_LEN * 6];
    char cmdline_escaped[MAX_CMDLINE_LEN * 6];
    char username[USERNAME_MAX];
    char username_escaped[USERNAME_MAX * 6];
    char sha256[SHA256_HEX_LEN];
    const char *event_type;

    if (!log_fp)
        return -EINVAL;

    format_timestamp(timestamp, sizeof(timestamp));

    switch (event->type) {
    case EVENT_PROCESS_EXEC:
        event_type = "process_exec";
        break;
    case EVENT_PROCESS_EXIT:
        event_type = "process_exit";
        break;
    default:
        event_type = "unknown";
    }

    json_escape(event->comm, comm_escaped, sizeof(comm_escaped));
    json_escape(hostname, hostname_escaped, sizeof(hostname_escaped));

    // Resolve username if enabled
    if (enable_resolve_usernames) {
        userdb_resolve(event->uid, username, sizeof(username));
        json_escape(username, username_escaped, sizeof(username_escaped));
    }

    // Resolve sudo username if we have sudo_uid from eBPF
    char sudo_user[USERNAME_MAX] = {0};
    char sudo_user_escaped[USERNAME_MAX * 6];

    if (event->sudo_uid > 0 && enable_resolve_usernames) {
        userdb_resolve(event->sudo_uid, sudo_user, sizeof(sudo_user));
        json_escape(sudo_user, sudo_user_escaped, sizeof(sudo_user_escaped));
    }

    // Get sequence number for tamper detection
    pthread_mutex_lock(&seq_mutex);
    uint64_t seq = ++event_sequence;
    event_count++;
    pthread_mutex_unlock(&seq_mutex);

    pthread_mutex_lock(&log_mutex);

    // Write JSON header - critical section, check for errors to avoid truncated events
    int ret = fprintf(log_fp,
            "{\"seq\":%lu,\"timestamp\":\"%s\",\"hostname\":\"%s\",\"type\":\"%s\",\"pid\":%u,\"ppid\":%u,"
            "\"sid\":%u,\"pgid\":%u,"
            "\"uid\":%u",
            seq, timestamp, hostname_escaped, event_type, event->pid, event->ppid,
            event->sid, event->pgid,
            event->uid);

    if (!check_fprintf_result(ret)) {
        pthread_mutex_unlock(&log_mutex);
        return -EIO;  // Critical failure, abort event logging
    }

    if (enable_resolve_usernames) {
        fprintf(log_fp, ",\"username\":\"%s\"", username_escaped);
    }

    // Add sudo context if process is running via sudo (from eBPF)
    if (event->sudo_uid > 0) {
        fprintf(log_fp, ",\"sudo_uid\":%u", event->sudo_uid);
        if (sudo_user[0]) {
            fprintf(log_fp, ",\"sudo_user\":\"%s\"", sudo_user_escaped);
        }
    }

    // TTY field - empty string means no controlling terminal (background process)
    if (event->tty[0]) {
        char tty_escaped[16 * 6];
        json_escape(event->tty, tty_escaped, sizeof(tty_escaped));
        fprintf(log_fp, ",\"tty\":\"%s\"", tty_escaped);
    } else {
        fprintf(log_fp, ",\"tty\":\"\"");
    }

    fprintf(log_fp, ",\"comm\":\"%s\"", comm_escaped);

    if (event->filename[0]) {
        json_escape(event->filename, filename_escaped, sizeof(filename_escaped));
        fprintf(log_fp, ",\"filename\":\"%s\"", filename_escaped);

        // Check for deleted executable in filename path
        bool deleted_exec = (strstr(event->filename, " (deleted)") != NULL);

        // Extract process_name (basename) from filename
        const char *process_name = strrchr(event->filename, '/');
        if (process_name) {
            process_name++;  // Skip the '/'
        } else {
            process_name = event->filename;  // No slash, use full filename
        }

        // Strip " (deleted)" suffix from process_name if present
        char clean_process_name[MAX_FILENAME_LEN];
        strncpy(clean_process_name, process_name, sizeof(clean_process_name) - 1);
        clean_process_name[sizeof(clean_process_name) - 1] = '\0';
        char *deleted_marker = strstr(clean_process_name, " (deleted)");
        if (deleted_marker) {
            *deleted_marker = '\0';
        }

        char process_name_escaped[MAX_FILENAME_LEN * 6];
        json_escape(clean_process_name, process_name_escaped, sizeof(process_name_escaped));
        fprintf(log_fp, ",\"process_name\":\"%s\"", process_name_escaped);

        // Check for comm mismatch (masquerading detection)
        if (is_comm_mismatch(event->comm, clean_process_name)) {
            fprintf(log_fp, ",\"comm_mismatch\":true");
        }

        // Log if executable was deleted
        if (deleted_exec) {
            fprintf(log_fp, ",\"deleted_executable\":true");
        }

        // Hash binary if enabled and this is an exec event
        if (enable_hash_binaries && event->type == EVENT_PROCESS_EXEC) {
            if (filehash_calculate(event->filename, sha256, sizeof(sha256))) {
                fprintf(log_fp, ",\"sha256\":\"%s\"", sha256);
            }
        }

        // Verify package ownership if enabled and this is an exec event
        if (enable_verify_packages && event->type == EVENT_PROCESS_EXEC) {
            struct pkg_info pkg;
            if (pkgcache_lookup(event->filename, &pkg) == 0) {
                if (pkg.from_package && pkg.package[0]) {
                    char pkg_escaped[PKG_NAME_MAX * 6];
                    json_escape(pkg.package, pkg_escaped, sizeof(pkg_escaped));
                    fprintf(log_fp, ",\"package\":\"%s\"", pkg_escaped);
                } else {
                    fprintf(log_fp, ",\"package\":null");
                }
                if (pkg.modified) {
                    fprintf(log_fp, ",\"pkg_modified\":true");
                }
            }
        }
    }

    if (event->cmdline[0]) {
        json_escape(event->cmdline, cmdline_escaped, sizeof(cmdline_escaped));
        fprintf(log_fp, ",\"cmdline\":\"%s\"", cmdline_escaped);
    }

    if (event->type == EVENT_PROCESS_EXIT) {
        fprintf(log_fp, ",\"exit_code\":%d", (int)event->exit_code);
    }

    // Log container info (sparse - only if in container)
    log_container_info(event->pid, event->pid_ns, event->mnt_ns, event->net_ns);

    ret = fprintf(log_fp, "}\n");

    // Prepare syslog data BEFORE unlocking mutex (collect all needed variables)
    // This avoids holding mutex during syslog() call (which can block)
    char syslog_buf[2048];
    bool need_syslog = enable_syslog;

    if (need_syslog && event->type == EVENT_PROCESS_EXEC) {
        size_t pos = 0;

        // Base event info: seq, hostname, user, process
        syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                     "%s: seq=%lu host=%s user=%s(%u)",
                     event_type, seq, hostname, username, event->uid);

        // sudo tracking (if applicable)
        if (event->sudo_uid > 0 && sudo_user[0]) {
            syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                         " sudo=%s(%u)", sudo_user, event->sudo_uid);
        }

        // TTY and process hierarchy
        if (event->tty[0]) {
            syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                         " tty=%s", event->tty);
        }
        syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                     " pid=%u ppid=%u sid=%u", event->pid, event->ppid, event->sid);

        // Process name and comm
        syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                     " comm=%s", event->comm);

        // File path
        if (event->filename[0]) {
            syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                         " file=%s", event->filename);
        }

        // Package info (re-lookup since pkg was scoped)
        if (enable_verify_packages && event->filename[0]) {
            struct pkg_info pkg;
            if (pkgcache_lookup(event->filename, &pkg) == 0) {
                if (pkg.from_package && pkg.package[0]) {
                    syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                                 " pkg=%s", pkg.package);
                    if (pkg.modified) {
                        syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                                     " modified=yes");
                    }
                } else {
                    syslog_append(syslog_buf, sizeof(syslog_buf), &pos, " pkg=none");
                }
            }
        }

        // SHA256 (abbreviated for syslog)
        if (sha256[0]) {
            syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                         " sha256=%.16s", sha256);  // First 16 chars
        }

        // Container info (sparse)
        if (containerinfo_is_in_container(event->pid_ns, event->mnt_ns, event->net_ns)) {
            struct container_info cinfo;
            if (containerinfo_get(event->pid, &cinfo)) {
                syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                             " container=%s", container_runtime_name(&cinfo));
                if (cinfo.id[0]) {
                    syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                                 " cid=%.12s", cinfo.id);  // Docker-style short ID
                }
            }
        }

        // Command line (last, can be long - use escaped version)
        if (event->cmdline[0]) {
            syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                         " cmd=\"%s\"", cmdline_escaped);
        }
    } else if (need_syslog) {
        // Process exit - simpler format
        snprintf(syslog_buf, sizeof(syslog_buf),
                "%s: seq=%lu host=%s user=%s(%u) pid=%u exit_code=%d comm=%s",
                event_type, seq, hostname, username, event->uid,
                event->pid, (int)event->exit_code, event->comm);
    }

    pthread_mutex_unlock(&log_mutex);

    if (!check_fprintf_result(ret))
        return -EIO;

    // Log to syslog AFTER mutex unlock (avoids blocking while holding lock)
    if (need_syslog) {
        syslog(LOG_INFO, "%s", syslog_buf);
    }

    return 0;
}

int logger_log_file_event(const struct file_event *event)
{
    char timestamp[64];
    char hostname_escaped[256 * 6];
    char comm_escaped[TASK_COMM_LEN * 6];
    char filename_escaped[MAX_FILENAME_LEN * 6];
    char username[USERNAME_MAX];
    char username_escaped[USERNAME_MAX * 6];
    const char *event_type;
    int ret;

    if (!log_fp)
        return -EINVAL;

    format_timestamp(timestamp, sizeof(timestamp));

    switch (event->type) {
    case EVENT_FILE_OPEN:
        event_type = "file_open";
        break;
    case EVENT_FILE_CREATE:
        event_type = "file_create";
        break;
    case EVENT_FILE_DELETE:
        event_type = "file_delete";
        break;
    case EVENT_FILE_MODIFY:
        event_type = "file_modify";
        break;
    default:
        event_type = "file_unknown";
    }

    json_escape(event->comm, comm_escaped, sizeof(comm_escaped));
    json_escape(event->filename, filename_escaped, sizeof(filename_escaped));
    json_escape(hostname, hostname_escaped, sizeof(hostname_escaped));

    if (enable_resolve_usernames) {
        userdb_resolve(event->uid, username, sizeof(username));
        json_escape(username, username_escaped, sizeof(username_escaped));
    }

    // Get sequence number for tamper detection
    pthread_mutex_lock(&seq_mutex);
    uint64_t seq = ++event_sequence;
    event_count++;
    pthread_mutex_unlock(&seq_mutex);

    pthread_mutex_lock(&log_mutex);

    // Write JSON header - critical section, check for errors to avoid truncated events
    ret = fprintf(log_fp,
            "{\"seq\":%lu,\"timestamp\":\"%s\",\"hostname\":\"%s\",\"type\":\"%s\",\"pid\":%u,\"ppid\":%u,"
            "\"sid\":%u,\"pgid\":%u,\"uid\":%u",
            seq, timestamp, hostname_escaped, event_type, event->pid, event->ppid,
            event->sid, event->pgid, event->uid);

    if (!check_fprintf_result(ret)) {
        pthread_mutex_unlock(&log_mutex);
        return -EIO;  // Critical failure, abort event logging
    }

    if (enable_resolve_usernames) {
        fprintf(log_fp, ",\"username\":\"%s\"", username_escaped);
    }

    // TTY field
    if (event->tty[0]) {
        char tty_escaped[16 * 6];
        json_escape(event->tty, tty_escaped, sizeof(tty_escaped));
        fprintf(log_fp, ",\"tty\":\"%s\"", tty_escaped);
    } else {
        fprintf(log_fp, ",\"tty\":\"\"");
    }

    fprintf(log_fp, ",\"comm\":\"%s\",\"filename\":\"%s\"", comm_escaped, filename_escaped);

    // Extract process_name (basename) from filename
    const char *process_name = strrchr(event->filename, '/');
    if (process_name) {
        process_name++;  // Skip the '/'
    } else {
        process_name = event->filename;  // No slash, use full filename
    }
    char process_name_escaped[MAX_FILENAME_LEN * 6];
    json_escape(process_name, process_name_escaped, sizeof(process_name_escaped));
    fprintf(log_fp, ",\"process_name\":\"%s\"", process_name_escaped);

    fprintf(log_fp, ",\"flags\":%u", event->flags);

    // Log container info (sparse - only if in container)
    log_container_info(event->pid, event->pid_ns, event->mnt_ns, event->net_ns);

    ret = fprintf(log_fp, "}\n");

    pthread_mutex_unlock(&log_mutex);

    if (!check_fprintf_result(ret))
        return -EIO;

    // Log to syslog if enabled
    if (enable_syslog) {
        syslog(LOG_INFO, "%s: pid=%u uid=%u comm=%s filename=\"%s\"",
               event_type, event->pid, event->uid, event->comm,
               filename_escaped);
    }

    return 0;
}

int logger_log_network_event(const struct network_event *event)
{
    char timestamp[64];
    char hostname_escaped[256 * 6];
    char comm_escaped[TASK_COMM_LEN * 6];
    char username[USERNAME_MAX];
    char username_escaped[USERNAME_MAX * 6];
    char saddr_str[INET6_ADDRSTRLEN];
    char daddr_str[INET6_ADDRSTRLEN];
    const char *event_type;
    int ret;

    if (!log_fp)
        return -EINVAL;

    format_timestamp(timestamp, sizeof(timestamp));

    switch (event->type) {
    case EVENT_NET_CONNECT_TCP:
        event_type = "net_connect_tcp";
        break;
    case EVENT_NET_ACCEPT_TCP:
        event_type = "net_accept_tcp";
        break;
    case EVENT_NET_SEND_UDP:
        event_type = "net_send_udp";
        break;
    case EVENT_NET_VSOCK_CONNECT:
        event_type = "net_vsock_connect";
        break;
    default:
        event_type = "net_unknown";
    }

    json_escape(event->comm, comm_escaped, sizeof(comm_escaped));
    json_escape(hostname, hostname_escaped, sizeof(hostname_escaped));

    if (enable_resolve_usernames) {
        userdb_resolve(event->uid, username, sizeof(username));
        json_escape(username, username_escaped, sizeof(username_escaped));
    }

    // Format IP addresses based on family
    if (event->family == AF_INET) {
        // IPv4 - read from first 4 bytes
        struct in_addr addr4;
        memcpy(&addr4, event->saddr, 4);
        inet_ntop(AF_INET, &addr4, saddr_str, sizeof(saddr_str));
        memcpy(&addr4, event->daddr, 4);
        inet_ntop(AF_INET, &addr4, daddr_str, sizeof(daddr_str));
    } else if (event->family == AF_INET6) {
        // IPv6 - use all 16 bytes
        inet_ntop(AF_INET6, event->saddr, saddr_str, sizeof(saddr_str));
        inet_ntop(AF_INET6, event->daddr, daddr_str, sizeof(daddr_str));
    } else if (event->family == 40) {  // AF_VSOCK
        // vsock - CID (Context ID) stored in first 4 bytes
        uint32_t scid, dcid;
        memcpy(&scid, event->saddr, 4);
        memcpy(&dcid, event->daddr, 4);
        snprintf(saddr_str, sizeof(saddr_str), "%u", scid);
        snprintf(daddr_str, sizeof(daddr_str), "%u", dcid);
    } else {
        snprintf(saddr_str, sizeof(saddr_str), "unknown");
        snprintf(daddr_str, sizeof(daddr_str), "unknown");
    }

    // Get sequence number for tamper detection
    pthread_mutex_lock(&seq_mutex);
    uint64_t seq = ++event_sequence;
    event_count++;
    pthread_mutex_unlock(&seq_mutex);

    pthread_mutex_lock(&log_mutex);

    // Write JSON header - critical section, check for errors to avoid truncated events
    ret = fprintf(log_fp,
            "{\"seq\":%lu,\"timestamp\":\"%s\",\"hostname\":\"%s\",\"type\":\"%s\",\"pid\":%u,\"ppid\":%u,"
            "\"sid\":%u,\"pgid\":%u,\"uid\":%u",
            seq, timestamp, hostname_escaped, event_type, event->pid, event->ppid,
            event->sid, event->pgid, event->uid);

    if (!check_fprintf_result(ret)) {
        pthread_mutex_unlock(&log_mutex);
        return -EIO;  // Critical failure, abort event logging
    }

    if (enable_resolve_usernames) {
        fprintf(log_fp, ",\"username\":\"%s\"", username_escaped);
    }

    // TTY field
    if (event->tty[0]) {
        char tty_escaped[16 * 6];
        json_escape(event->tty, tty_escaped, sizeof(tty_escaped));
        fprintf(log_fp, ",\"tty\":\"%s\"", tty_escaped);
    } else {
        fprintf(log_fp, ",\"tty\":\"\"");
    }

    fprintf(log_fp, ",\"comm\":\"%s\"", comm_escaped);

    // Try to get process_name from /proc/<pid>/exe
    char process_name[PATH_MAX];
    bool deleted_exec = false;
    if (get_process_name_from_proc(event->pid, process_name, sizeof(process_name), &deleted_exec)) {
        char process_name_escaped[PATH_MAX * 6];
        json_escape(process_name, process_name_escaped, sizeof(process_name_escaped));
        fprintf(log_fp, ",\"process_name\":\"%s\"", process_name_escaped);

        // Check for comm mismatch (masquerading detection)
        if (is_comm_mismatch(event->comm, process_name)) {
            fprintf(log_fp, ",\"comm_mismatch\":true");
        }

        // Log if executable was deleted
        if (deleted_exec) {
            fprintf(log_fp, ",\"deleted_executable\":true");
        }
    } else {
        fprintf(log_fp, ",\"process_name\":null");
    }

    fprintf(log_fp, ",\"saddr\":\"%s\","
            "\"daddr\":\"%s\",\"sport\":%u,\"dport\":%u",
            saddr_str, daddr_str,
            event->sport, event->dport);

    // Log container info (sparse - only if in container)
    log_container_info(event->pid, event->pid_ns, event->mnt_ns, event->net_ns);

    ret = fprintf(log_fp, "}\n");

    // Prepare syslog data BEFORE unlocking mutex
    char syslog_buf[1024];
    bool need_syslog = enable_syslog;

    if (need_syslog) {
        size_t pos = 0;
        syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                     "%s: seq=%lu host=%s user=%s(%u) pid=%u comm=%s %s:%u->%s:%u",
                     event_type, seq, hostname, username, event->uid,
                     event->pid, event->comm,
                     saddr_str, event->sport, daddr_str, event->dport);
    }

    pthread_mutex_unlock(&log_mutex);

    if (!check_fprintf_result(ret))
        return -EIO;

    // Log to syslog AFTER mutex unlock
    if (need_syslog) {
        syslog(LOG_INFO, "%s", syslog_buf);
    }

    return 0;
}

int logger_log_privilege_event(const struct privilege_event *event)
{
    char timestamp[64];
    char hostname_escaped[256 * 6];
    char comm_escaped[TASK_COMM_LEN * 6];
    char target_escaped[TASK_COMM_LEN * 6];
    char old_username[USERNAME_MAX];
    char new_username[USERNAME_MAX];
    char old_username_escaped[USERNAME_MAX * 6];
    char new_username_escaped[USERNAME_MAX * 6];
    const char *event_type;
    int ret;

    if (!log_fp)
        return -EINVAL;

    format_timestamp(timestamp, sizeof(timestamp));

    switch (event->type) {
    case EVENT_PRIV_SETUID:
        event_type = "priv_setuid";
        break;
    case EVENT_PRIV_SETGID:
        event_type = "priv_setgid";
        break;
    case EVENT_PRIV_SUDO:
        event_type = "priv_sudo";
        break;
    default:
        event_type = "priv_unknown";
    }

    json_escape(event->comm, comm_escaped, sizeof(comm_escaped));
    json_escape(hostname, hostname_escaped, sizeof(hostname_escaped));

    if (enable_resolve_usernames) {
        userdb_resolve(event->old_uid, old_username, sizeof(old_username));
        userdb_resolve(event->new_uid, new_username, sizeof(new_username));
        json_escape(old_username, old_username_escaped, sizeof(old_username_escaped));
        json_escape(new_username, new_username_escaped, sizeof(new_username_escaped));
    }

    // Get sequence number for tamper detection
    pthread_mutex_lock(&seq_mutex);
    uint64_t seq = ++event_sequence;
    event_count++;
    pthread_mutex_unlock(&seq_mutex);

    pthread_mutex_lock(&log_mutex);

    fprintf(log_fp,
            "{\"seq\":%lu,\"timestamp\":\"%s\",\"hostname\":\"%s\",\"type\":\"%s\",\"pid\":%u,\"ppid\":%u,"
            "\"sid\":%u,\"pgid\":%u,\"old_uid\":%u",
            seq, timestamp, hostname_escaped, event_type, event->pid, event->ppid,
            event->sid, event->pgid, event->old_uid);

    if (enable_resolve_usernames) {
        fprintf(log_fp, ",\"old_username\":\"%s\"", old_username_escaped);
    }

    fprintf(log_fp, ",\"new_uid\":%u", event->new_uid);

    if (enable_resolve_usernames) {
        fprintf(log_fp, ",\"new_username\":\"%s\"", new_username_escaped);
    }

    fprintf(log_fp, ",\"old_gid\":%u,\"new_gid\":%u",
            event->old_gid, event->new_gid);

    // TTY field
    if (event->tty[0]) {
        char tty_escaped[16 * 6];
        json_escape(event->tty, tty_escaped, sizeof(tty_escaped));
        fprintf(log_fp, ",\"tty\":\"%s\"", tty_escaped);
    } else {
        fprintf(log_fp, ",\"tty\":\"\"");
    }

    fprintf(log_fp, ",\"comm\":\"%s\"", comm_escaped);

    // Try to get process_name from /proc/<pid>/exe
    char process_name[PATH_MAX];
    bool deleted_exec = false;
    if (get_process_name_from_proc(event->pid, process_name, sizeof(process_name), &deleted_exec)) {
        char process_name_escaped[PATH_MAX * 6];
        json_escape(process_name, process_name_escaped, sizeof(process_name_escaped));
        fprintf(log_fp, ",\"process_name\":\"%s\"", process_name_escaped);

        // Check for comm mismatch (masquerading detection)
        if (is_comm_mismatch(event->comm, process_name)) {
            fprintf(log_fp, ",\"comm_mismatch\":true");
        }

        // Log if executable was deleted
        if (deleted_exec) {
            fprintf(log_fp, ",\"deleted_executable\":true");
        }
    } else {
        fprintf(log_fp, ",\"process_name\":null");
    }

    if (event->target_comm[0]) {
        json_escape(event->target_comm, target_escaped, sizeof(target_escaped));
        fprintf(log_fp, ",\"target\":\"%s\"", target_escaped);
    }

    // Log container info (sparse - only if in container)
    log_container_info(event->pid, event->pid_ns, event->mnt_ns, event->net_ns);

    ret = fprintf(log_fp, "}\n");

    // Prepare syslog data BEFORE unlocking mutex
    char syslog_buf[1024];
    bool need_syslog = enable_syslog;

    if (need_syslog) {
        size_t pos = 0;
        syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                     "%s: seq=%lu host=%s pid=%u comm=%s %s(%u)->%s(%u)",
                     event_type, seq, hostname, event->pid, event->comm,
                     old_username, event->old_uid, new_username, event->new_uid);

        // Add target process for sudo events
        if (event->target_comm[0]) {
            syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                         " target=%s", event->target_comm);
        }
    }

    pthread_mutex_unlock(&log_mutex);

    if (!check_fprintf_result(ret))
        return -EIO;

    // Log to syslog AFTER mutex unlock (privilege events use LOG_WARNING)
    if (need_syslog) {
        syslog(LOG_WARNING, "%s", syslog_buf);
    }

    return 0;
}

int logger_log_security_event(const struct security_event *event)
{
    char timestamp[64];
    char hostname_escaped[256 * 6];
    char comm_escaped[TASK_COMM_LEN * 6];
    char filename_escaped[MAX_FILENAME_LEN * 6];
    char username[USERNAME_MAX];
    char username_escaped[USERNAME_MAX * 6];
    const char *event_type;
    int ret;

    if (!log_fp)
        return -EINVAL;

    format_timestamp(timestamp, sizeof(timestamp));

    switch (event->type) {
    case EVENT_SECURITY_PTRACE:
        event_type = "security_ptrace";
        break;
    case EVENT_SECURITY_MODULE:
        event_type = "security_module_load";
        break;
    case EVENT_SECURITY_MEMFD:
        event_type = "security_memfd_create";
        break;
    case EVENT_SECURITY_BIND:
        event_type = "security_bind";
        break;
    case EVENT_SECURITY_UNSHARE:
        event_type = "security_unshare";
        break;
    case EVENT_SECURITY_EXECVEAT:
        event_type = "security_execveat";
        break;
    case EVENT_SECURITY_BPF:
        event_type = "security_bpf";
        break;
    case EVENT_SECURITY_CRED_READ:
        event_type = "security_cred_read";
        break;
    case EVENT_SECURITY_LDPRELOAD:
        event_type = "security_ldpreload";
        break;
    case EVENT_SECURITY_SUID:
        event_type = "security_suid";
        break;
    case EVENT_SECURITY_CRED_WRITE:
        event_type = "security_cred_write";
        break;
    case EVENT_SECURITY_LOG_TAMPER:
        event_type = "security_log_tamper";
        break;
    case EVENT_RAW_DISK_ACCESS:
        event_type = "raw_disk_access";
        break;
    default:
        event_type = "security_unknown";
    }

    json_escape(event->comm, comm_escaped, sizeof(comm_escaped));
    json_escape(hostname, hostname_escaped, sizeof(hostname_escaped));

    if (enable_resolve_usernames) {
        userdb_resolve(event->uid, username, sizeof(username));
        json_escape(username, username_escaped, sizeof(username_escaped));
    }

    // Get sequence number for tamper detection
    pthread_mutex_lock(&seq_mutex);
    uint64_t seq = ++event_sequence;
    event_count++;
    pthread_mutex_unlock(&seq_mutex);

    pthread_mutex_lock(&log_mutex);

    // Write JSON header - critical section, check for errors to avoid truncated events
    ret = fprintf(log_fp,
            "{\"seq\":%lu,\"timestamp\":\"%s\",\"hostname\":\"%s\",\"type\":\"%s\",\"pid\":%u,\"ppid\":%u,"
            "\"sid\":%u,\"pgid\":%u,\"uid\":%u",
            seq, timestamp, hostname_escaped, event_type, event->pid, event->ppid,
            event->sid, event->pgid, event->uid);

    if (!check_fprintf_result(ret)) {
        pthread_mutex_unlock(&log_mutex);
        return -EIO;  // Critical failure, abort event logging
    }

    if (enable_resolve_usernames) {
        fprintf(log_fp, ",\"username\":\"%s\"", username_escaped);
    }

    // TTY field
    if (event->tty[0]) {
        char tty_escaped[16 * 6];
        json_escape(event->tty, tty_escaped, sizeof(tty_escaped));
        fprintf(log_fp, ",\"tty\":\"%s\"", tty_escaped);
    } else {
        fprintf(log_fp, ",\"tty\":\"\"");
    }

    fprintf(log_fp, ",\"comm\":\"%s\"", comm_escaped);

    // Try to get process_name from /proc/<pid>/exe
    char process_name[PATH_MAX];
    bool deleted_exec = false;
    if (get_process_name_from_proc(event->pid, process_name, sizeof(process_name), &deleted_exec)) {
        char process_name_escaped[PATH_MAX * 6];
        json_escape(process_name, process_name_escaped, sizeof(process_name_escaped));
        fprintf(log_fp, ",\"process_name\":\"%s\"", process_name_escaped);

        // Check for comm mismatch (masquerading detection)
        if (is_comm_mismatch(event->comm, process_name)) {
            fprintf(log_fp, ",\"comm_mismatch\":true");
        }

        // Log if executable was deleted
        if (deleted_exec) {
            fprintf(log_fp, ",\"deleted_executable\":true");
        }
    } else {
        fprintf(log_fp, ",\"process_name\":null");
    }

    // Type-specific fields
    if (event->type == EVENT_SECURITY_PTRACE) {
        fprintf(log_fp, ",\"target_pid\":%u,\"ptrace_request\":%u",
                event->target_pid, event->flags);
    } else if (event->type == EVENT_SECURITY_MODULE) {
        fprintf(log_fp, ",\"module_flags\":%u", event->flags);
    } else if (event->type == EVENT_SECURITY_MEMFD) {
        if (event->filename[0]) {
            json_escape(event->filename, filename_escaped, sizeof(filename_escaped));
            fprintf(log_fp, ",\"memfd_name\":\"%s\"", filename_escaped);
        }
        fprintf(log_fp, ",\"memfd_flags\":%u", event->flags);
    } else if (event->type == EVENT_SECURITY_BIND) {
        fprintf(log_fp, ",\"port\":%u,\"family\":%u,\"fd\":%u",
                event->port, event->family, event->target_pid);
    } else if (event->type == EVENT_SECURITY_UNSHARE) {
        fprintf(log_fp, ",\"unshare_flags\":%u", event->flags);
    } else if (event->type == EVENT_SECURITY_EXECVEAT) {
        fprintf(log_fp, ",\"dirfd\":%d,\"at_flags\":%u",
                (int)event->target_pid, event->extra);
        if (event->filename[0]) {
            json_escape(event->filename, filename_escaped, sizeof(filename_escaped));
            fprintf(log_fp, ",\"pathname\":\"%s\"", filename_escaped);
        }
    } else if (event->type == EVENT_SECURITY_BPF) {
        fprintf(log_fp, ",\"bpf_cmd\":%u", event->extra);
    } else if (event->type == EVENT_SECURITY_CRED_READ) {
        // extra: 1=shadow, 2=gshadow, 3=sudoers, 4=ssh_config, 5=pam_config,
        //        6=ssh_private_key, 7=ssh_authorized_keys, 8=ssh_user_config
        const char *file_type;
        switch (event->extra) {
        case 1: file_type = "shadow"; break;
        case 2: file_type = "gshadow"; break;
        case 3: file_type = "sudoers"; break;
        case 4: file_type = "ssh_config"; break;
        case 5: file_type = "pam_config"; break;
        case 6: file_type = "ssh_private_key"; break;
        case 7: file_type = "ssh_authorized_keys"; break;
        case 8: file_type = "ssh_user_config"; break;
        default: file_type = "unknown"; break;
        }
        fprintf(log_fp, ",\"cred_file\":\"%s\",\"open_flags\":%u", file_type, event->flags);
        if (event->filename[0]) {
            json_escape(event->filename, filename_escaped, sizeof(filename_escaped));
            fprintf(log_fp, ",\"path\":\"%s\"", filename_escaped);
        }
    } else if (event->type == EVENT_SECURITY_LDPRELOAD) {
        fprintf(log_fp, ",\"open_flags\":%u", event->flags);
        if (event->filename[0]) {
            json_escape(event->filename, filename_escaped, sizeof(filename_escaped));
            fprintf(log_fp, ",\"path\":\"%s\"", filename_escaped);
        }
    } else if (event->type == EVENT_SECURITY_SUID) {
        // Output file path and mode bits
        if (event->filename[0]) {
            json_escape(event->filename, filename_escaped, sizeof(filename_escaped));
            fprintf(log_fp, ",\"path\":\"%s\"", filename_escaped);
        }
        fprintf(log_fp, ",\"mode\":%u", event->flags);
        fprintf(log_fp, ",\"suid\":%s", (event->flags & 04000) ? "true" : "false");
        fprintf(log_fp, ",\"sgid\":%s", (event->flags & 02000) ? "true" : "false");
    } else if (event->type == EVENT_SECURITY_CRED_WRITE) {
        // Credential file write (account manipulation)
        // extra: 1=shadow, 2=gshadow, 3=sudoers, 4=ssh_config, 5=pam_config,
        //        6=ssh_private_key, 7=ssh_authorized_keys, 8=ssh_user_config
        const char *file_type;
        switch (event->extra) {
        case 1: file_type = "shadow"; break;
        case 2: file_type = "gshadow"; break;
        case 3: file_type = "sudoers"; break;
        case 4: file_type = "ssh_config"; break;
        case 5: file_type = "pam_config"; break;
        case 6: file_type = "ssh_private_key"; break;
        case 7: file_type = "ssh_authorized_keys"; break;
        case 8: file_type = "ssh_user_config"; break;
        default: file_type = "unknown"; break;
        }
        fprintf(log_fp, ",\"cred_file\":\"%s\",\"open_flags\":%u", file_type, event->flags);
        if (event->filename[0]) {
            json_escape(event->filename, filename_escaped, sizeof(filename_escaped));
            fprintf(log_fp, ",\"path\":\"%s\"", filename_escaped);
        }
    } else if (event->type == EVENT_SECURITY_LOG_TAMPER) {
        // Log file tampering (anti-forensics)
        // extra: 1=truncate (O_TRUNC), 2=delete (unlink)
        const char *tamper_type = (event->extra == 1) ? "truncate" : "delete";
        fprintf(log_fp, ",\"tamper_type\":\"%s\"", tamper_type);
        if (event->filename[0]) {
            json_escape(event->filename, filename_escaped, sizeof(filename_escaped));
            fprintf(log_fp, ",\"path\":\"%s\"", filename_escaped);
        }
        if (event->extra == 1) {
            fprintf(log_fp, ",\"open_flags\":%u", event->flags);
        }
    } else if (event->type == EVENT_RAW_DISK_ACCESS) {
        // Raw disk write access (T1561 - Disk Wipe)
        if (event->filename[0]) {
            json_escape(event->filename, filename_escaped, sizeof(filename_escaped));
            fprintf(log_fp, ",\"device\":\"%s\"", filename_escaped);
        }
        fprintf(log_fp, ",\"open_flags\":%u", event->flags);
        // Indicate write intent
        bool wronly = (event->flags & O_WRONLY) != 0;
        bool rdwr = (event->flags & O_RDWR) != 0;
        fprintf(log_fp, ",\"write_access\":%s", (wronly || rdwr) ? "true" : "false");
    }

    // Log container info (sparse - only if in container)
    log_container_info(event->pid, event->pid_ns, event->mnt_ns, event->net_ns);

    ret = fprintf(log_fp, "}\n");

    // Prepare syslog data BEFORE unlocking mutex (security events are critical)
    char syslog_buf[1024];
    bool need_syslog = enable_syslog;

    if (need_syslog) {
        size_t pos = 0;
        syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                     "SECURITY: seq=%lu type=%s host=%s user=%s(%u) pid=%u comm=%s",
                     seq, event_type, hostname, username, event->uid,
                     event->pid, event->comm);

        // Add event-specific critical fields
        switch (event->type) {
        case EVENT_SECURITY_PTRACE:
            if (event->target_pid) {
                syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                             " target_pid=%u", event->target_pid);
            }
            break;
        case EVENT_SECURITY_MEMFD:
            if (event->filename[0]) {  // memfd_name is stored in filename field
                syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                             " memfd=%s", event->filename);
            }
            break;
        case EVENT_SECURITY_CRED_READ:
        case EVENT_SECURITY_CRED_WRITE:
            // Map event->extra to credential file type name
            {
                const char *cred_type = "unknown";
                switch (event->extra) {
                case 1: cred_type = "shadow"; break;
                case 2: cred_type = "gshadow"; break;
                case 3: cred_type = "sudoers"; break;
                case 4: cred_type = "ssh_config"; break;
                case 5: cred_type = "pam_config"; break;
                case 6: cred_type = "ssh_private_key"; break;
                case 7: cred_type = "ssh_authorized_keys"; break;
                case 8: cred_type = "ssh_user_config"; break;
                }
                syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                             " cred_file=%s", cred_type);
                if (event->filename[0]) {  // Full path
                    syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                                 " path=%s", event->filename);
                }
            }
            break;
        case EVENT_SECURITY_LOG_TAMPER:
        case EVENT_SECURITY_SUID:
        case EVENT_RAW_DISK_ACCESS:
            if (event->filename[0]) {
                syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                             " file=%s", event->filename);
            }
            break;
        default:
            break;
        }
    }

    pthread_mutex_unlock(&log_mutex);

    if (!check_fprintf_result(ret))
        return -EIO;

    // Log to syslog AFTER mutex unlock (security events use LOG_WARNING for visibility)
    if (need_syslog) {
        syslog(LOG_WARNING, "%s", syslog_buf);
    }

    return 0;
}

int logger_log_persistence_event(const struct persistence_event *event)
{
    const char *persistence_names[] = {
        "unknown",        // 0
        "cron",          // 1
        "systemd",       // 2
        "shell_profile", // 3
        "init",          // 4
        "autostart"      // 5
    };

    char timestamp[64];
    char hostname_escaped[256 * 6];
    char comm_escaped[TASK_COMM_LEN * 6];
    char path_escaped[MAX_FILENAME_LEN * 6];
    char username[USERNAME_MAX];
    char username_escaped[USERNAME_MAX * 6];
    int ret;

    if (!log_fp)
        return -EINVAL;

    format_timestamp(timestamp, sizeof(timestamp));

    json_escape(event->comm, comm_escaped, sizeof(comm_escaped));
    json_escape(event->path, path_escaped, sizeof(path_escaped));
    json_escape(hostname, hostname_escaped, sizeof(hostname_escaped));

    if (enable_resolve_usernames) {
        userdb_resolve(event->uid, username, sizeof(username));
        json_escape(username, username_escaped, sizeof(username_escaped));
    }

    // Get sequence number for tamper detection
    pthread_mutex_lock(&seq_mutex);
    uint64_t seq = ++event_sequence;
    event_count++;
    pthread_mutex_unlock(&seq_mutex);

    pthread_mutex_lock(&log_mutex);

    fprintf(log_fp,
            "{\"seq\":%lu,\"timestamp\":\"%s\",\"hostname\":\"%s\",\"type\":\"security_persistence\",\"pid\":%u,\"ppid\":%u,"
            "\"sid\":%u,\"pgid\":%u,\"uid\":%u",
            seq, timestamp, hostname_escaped, event->pid, event->ppid,
            event->sid, event->pgid, event->uid);

    if (enable_resolve_usernames) {
        fprintf(log_fp, ",\"username\":\"%s\"", username_escaped);
    }

    // TTY field
    if (event->tty[0]) {
        char tty_escaped[16 * 6];
        json_escape(event->tty, tty_escaped, sizeof(tty_escaped));
        fprintf(log_fp, ",\"tty\":\"%s\"", tty_escaped);
    } else {
        fprintf(log_fp, ",\"tty\":\"\"");
    }

    fprintf(log_fp, ",\"comm\":\"%s\"", comm_escaped);
    fprintf(log_fp, ",\"path\":\"%s\"", path_escaped);

    // Bounds check: persistence_type comes from eBPF and must be validated
    // Array has 6 elements (indices 0-5), anything else is malformed data
    const char *persistence_type_str = "unknown";
    if (event->persistence_type > 0 && event->persistence_type <= 5) {
        persistence_type_str = persistence_names[event->persistence_type];
    }
    fprintf(log_fp, ",\"persistence_type\":\"%s\"", persistence_type_str);
    fprintf(log_fp, ",\"open_flags\":%u", event->flags);

    // Log container info (sparse - only if in container)
    log_container_info(event->pid, event->pid_ns, event->mnt_ns, event->net_ns);

    ret = fprintf(log_fp, "}\n");

    // Prepare syslog data BEFORE unlocking mutex
    char syslog_buf[1024];
    bool need_syslog = enable_syslog;

    if (need_syslog) {
        size_t pos = 0;
        syslog_append(syslog_buf, sizeof(syslog_buf), &pos,
                     "SECURITY: seq=%lu type=security_persistence host=%s user=%s(%u) "
                     "pid=%u comm=%s persistence=%s path=%s",
                     seq, hostname, username, event->uid,
                     event->pid, event->comm, persistence_type_str, event->path);
    }

    pthread_mutex_unlock(&log_mutex);

    if (!check_fprintf_result(ret))
        return -EIO;

    // Log to syslog AFTER mutex unlock (security events use LOG_WARNING)
    if (need_syslog) {
        syslog(LOG_WARNING, "%s", syslog_buf);
    }

    return 0;
}

FILE *logger_get_fp(void)
{
    return log_fp;
}

pthread_mutex_t *logger_get_mutex(void)
{
    return &log_mutex;
}

uint64_t logger_get_sequence(void)
{
    uint64_t seq;
    pthread_mutex_lock(&seq_mutex);
    seq = event_sequence;
    pthread_mutex_unlock(&seq_mutex);
    return seq;
}

unsigned long logger_get_event_count(void)
{
    unsigned long count;
    pthread_mutex_lock(&seq_mutex);
    count = event_count;
    pthread_mutex_unlock(&seq_mutex);
    return count;
}

bool logger_check_file_deleted(void)
{
    struct stat st;
    uint64_t last_seq;
    unsigned long lost_events;
    char timestamp[64];
    struct timespec ts;
    struct tm tm_info;

    pthread_mutex_lock(&log_mutex);

    // Check if current log file has been deleted
    if (!log_fp || fstat(fileno(log_fp), &st) != 0) {
        pthread_mutex_unlock(&log_mutex);
        return false;
    }

    // st_nlink == 0 means file is deleted from filesystem but still open
    if (st.st_nlink > 0) {
        pthread_mutex_unlock(&log_mutex);
        return false;  // File still exists, all good
    }

    // CRITICAL: Log file has been deleted (T1070.001 - Indicator Removal)

    // Save current sequence number and event count before recovery
    pthread_mutex_lock(&seq_mutex);
    last_seq = event_sequence;
    lost_events = event_count;
    pthread_mutex_unlock(&seq_mutex);

    pthread_mutex_unlock(&log_mutex);

    // Log to syslog (cannot be deleted, goes to journald)
    syslog(LOG_CRIT, "SECURITY ALERT: Log file deleted (T1070.001) - "
                     "last_seq=%lu events_lost=%lu - reopening new file",
           last_seq, lost_events);

    // Try to reopen log file
    const char *log_path = (rotation_base_path[0] != '\0') ? rotation_base_path : "/var/log/linmon/events.json";
    mode_t old_umask = umask(0027);  // rw-r----- permissions
    FILE *new_fp = fopen(log_path, "a");
    umask(old_umask);

    if (!new_fp) {
        syslog(LOG_CRIT, "CRITICAL: Failed to reopen log after deletion: %s",
               strerror(errno));
        return true;  // File was deleted, but recovery failed
    }

    setlinebuf(new_fp);

    // Replace old file pointer atomically
    logger_replace(new_fp);

    // Format timestamp
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm_info);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", &tm_info);
    snprintf(timestamp + strlen(timestamp), sizeof(timestamp) - strlen(timestamp),
             ".%03ldZ", ts.tv_nsec / 1000000);

    // Log recovery event to NEW file with gap information
    // This creates forensic trail even though original file is gone
    pthread_mutex_lock(&log_mutex);
    pthread_mutex_lock(&seq_mutex);
    uint64_t recovery_seq = ++event_sequence;
    event_count++;
    pthread_mutex_unlock(&seq_mutex);

    fprintf(log_fp,
            "{\"seq\":%lu,"
            "\"timestamp\":\"%s\","
            "\"hostname\":\"%s\","
            "\"type\":\"log_tamper_recovery\","
            "\"severity\":\"CRITICAL\","
            "\"attack_technique\":\"T1070.001\","
            "\"attack_name\":\"Indicator Removal: Clear Linux Logs\","
            "\"message\":\"Log file was deleted - sequence gap detected\","
            "\"last_seq_before_deletion\":%lu,"
            "\"events_lost\":%lu,"
            "\"recovery_seq\":%lu,"
            "\"seq_gap\":%lu}\n",
            recovery_seq,
            timestamp,
            hostname,
            last_seq,
            lost_events,
            recovery_seq,
            recovery_seq - last_seq);

    fflush(log_fp);
    pthread_mutex_unlock(&log_mutex);

    return true;  // File was deleted and recovered
}

void logger_cleanup(void)
{
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
}
