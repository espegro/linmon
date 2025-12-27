// SPDX-License-Identifier: GPL-2.0
// Event logging implementation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <limits.h>
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

static FILE *log_fp = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool enable_resolve_usernames = false;
static bool enable_hash_binaries = false;
static bool enable_verify_packages = false;
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
    log_fp = fopen(log_file, "a");
    if (!log_fp) {
        return -errno;
    }

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
                           bool verify_packages)
{
    enable_resolve_usernames = resolve_usernames;
    enable_hash_binaries = hash_binaries;
    enable_verify_packages = verify_packages;
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

    // Open fresh log file
    new_fp = fopen(rotation_base_path, "a");
    if (new_fp) {
        setlinebuf(new_fp);
        log_fp = new_fp;
        bytes_written = 0;
        fprintf(stderr, "Log rotated: %s\n", rotation_base_path);
    } else {
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

// Read executable path from /proc/<pid>/exe symlink and extract process_name (basename)
// Uses readlink() which works without CAP_SYS_PTRACE (only needs symlink read permission)
// Returns true if successful, false otherwise
// Sets process_name_out to basename of executable path
static bool get_process_name_from_proc(pid_t pid, char *process_name_out, size_t size)
{
    char proc_path[64];
    char exe_path[PATH_MAX];
    ssize_t len;

    if (!process_name_out || size == 0)
        return false;

    process_name_out[0] = '\0';

    // Read /proc/<pid>/exe symlink
    // readlink() works without CAP_SYS_PTRACE - only needs symlink read permission
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
    len = readlink(proc_path, exe_path, sizeof(exe_path) - 1);
    if (len == -1) {
        return false;  // Process may have exited or no permission
    }

    exe_path[len] = '\0';  // readlink() doesn't null-terminate

    // Extract basename from path
    const char *basename = strrchr(exe_path, '/');
    if (basename) {
        basename++;  // Skip the '/'
    } else {
        basename = exe_path;  // No slash, use full path
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

    fprintf(log_fp,
            "{\"seq\":%lu,\"timestamp\":\"%s\",\"hostname\":\"%s\",\"type\":\"%s\",\"pid\":%u,\"ppid\":%u,"
            "\"sid\":%u,\"pgid\":%u,"
            "\"uid\":%u",
            seq, timestamp, hostname_escaped, event_type, event->pid, event->ppid,
            event->sid, event->pgid,
            event->uid);

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

    int ret = fprintf(log_fp, "}\n");

    pthread_mutex_unlock(&log_mutex);

    if (!check_fprintf_result(ret))
        return -EIO;

    // Log to syslog if enabled
    if (enable_syslog) {
        if (event->cmdline[0]) {
            syslog(LOG_INFO, "%s: pid=%u uid=%u comm=%s cmdline=\"%s\"",
                   event_type, event->pid, event->uid, event->comm,
                   cmdline_escaped);
        } else {
            syslog(LOG_INFO, "%s: pid=%u uid=%u comm=%s",
                   event_type, event->pid, event->uid, event->comm);
        }
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

    fprintf(log_fp,
            "{\"seq\":%lu,\"timestamp\":\"%s\",\"hostname\":\"%s\",\"type\":\"%s\",\"pid\":%u,\"uid\":%u",
            seq, timestamp, hostname_escaped, event_type, event->pid, event->uid);

    if (enable_resolve_usernames) {
        fprintf(log_fp, ",\"username\":\"%s\"", username_escaped);
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

    int ret = fprintf(log_fp, ",\"flags\":%u}\n", event->flags);

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

    fprintf(log_fp,
            "{\"seq\":%lu,\"timestamp\":\"%s\",\"hostname\":\"%s\",\"type\":\"%s\",\"pid\":%u,"
            "\"uid\":%u",
            seq, timestamp, hostname_escaped, event_type, event->pid, event->uid);

    if (enable_resolve_usernames) {
        fprintf(log_fp, ",\"username\":\"%s\"", username_escaped);
    }

    fprintf(log_fp, ",\"comm\":\"%s\"", comm_escaped);

    // Try to get process_name from /proc/<pid>/exe
    char process_name[PATH_MAX];
    if (get_process_name_from_proc(event->pid, process_name, sizeof(process_name))) {
        char process_name_escaped[PATH_MAX * 6];
        json_escape(process_name, process_name_escaped, sizeof(process_name_escaped));
        fprintf(log_fp, ",\"process_name\":\"%s\"", process_name_escaped);
    } else {
        fprintf(log_fp, ",\"process_name\":null");
    }

    int ret = fprintf(log_fp, ",\"saddr\":\"%s\","
            "\"daddr\":\"%s\",\"sport\":%u,\"dport\":%u}\n",
            saddr_str, daddr_str,
            event->sport, event->dport);

    pthread_mutex_unlock(&log_mutex);

    if (!check_fprintf_result(ret))
        return -EIO;

    // Log to syslog if enabled
    if (enable_syslog) {
        syslog(LOG_INFO, "%s: pid=%u uid=%u comm=%s %s:%u -> %s:%u",
               event_type, event->pid, event->uid, event->comm,
               saddr_str, event->sport, daddr_str, event->dport);
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
            "{\"seq\":%lu,\"timestamp\":\"%s\",\"hostname\":\"%s\",\"type\":\"%s\",\"pid\":%u,"
            "\"old_uid\":%u",
            seq, timestamp, hostname_escaped, event_type, event->pid,
            event->old_uid);

    if (enable_resolve_usernames) {
        fprintf(log_fp, ",\"old_username\":\"%s\"", old_username_escaped);
    }

    fprintf(log_fp, ",\"new_uid\":%u", event->new_uid);

    if (enable_resolve_usernames) {
        fprintf(log_fp, ",\"new_username\":\"%s\"", new_username_escaped);
    }

    fprintf(log_fp, ",\"old_gid\":%u,\"new_gid\":%u,"
            "\"comm\":\"%s\"",
            event->old_gid, event->new_gid,
            comm_escaped);

    // Try to get process_name from /proc/<pid>/exe
    char process_name[PATH_MAX];
    if (get_process_name_from_proc(event->pid, process_name, sizeof(process_name))) {
        char process_name_escaped[PATH_MAX * 6];
        json_escape(process_name, process_name_escaped, sizeof(process_name_escaped));
        fprintf(log_fp, ",\"process_name\":\"%s\"", process_name_escaped);
    } else {
        fprintf(log_fp, ",\"process_name\":null");
    }

    if (event->target_comm[0]) {
        json_escape(event->target_comm, target_escaped, sizeof(target_escaped));
        fprintf(log_fp, ",\"target\":\"%s\"", target_escaped);
    }

    int ret = fprintf(log_fp, "}\n");

    pthread_mutex_unlock(&log_mutex);

    if (!check_fprintf_result(ret))
        return -EIO;

    // Log to syslog if enabled
    if (enable_syslog) {
        if (event->target_comm[0]) {
            syslog(LOG_WARNING, "%s: pid=%u uid=%u->%u comm=%s target=\"%s\"",
                   event_type, event->pid, event->old_uid, event->new_uid,
                   event->comm, target_escaped);
        } else {
            syslog(LOG_WARNING, "%s: pid=%u uid=%u->%u comm=%s",
                   event_type, event->pid, event->old_uid, event->new_uid,
                   event->comm);
        }
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

    fprintf(log_fp,
            "{\"seq\":%lu,\"timestamp\":\"%s\",\"hostname\":\"%s\",\"type\":\"%s\",\"pid\":%u,\"uid\":%u",
            seq, timestamp, hostname_escaped, event_type, event->pid, event->uid);

    if (enable_resolve_usernames) {
        fprintf(log_fp, ",\"username\":\"%s\"", username_escaped);
    }

    fprintf(log_fp, ",\"comm\":\"%s\"", comm_escaped);

    // Try to get process_name from /proc/<pid>/exe
    char process_name[PATH_MAX];
    if (get_process_name_from_proc(event->pid, process_name, sizeof(process_name))) {
        char process_name_escaped[PATH_MAX * 6];
        json_escape(process_name, process_name_escaped, sizeof(process_name_escaped));
        fprintf(log_fp, ",\"process_name\":\"%s\"", process_name_escaped);
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
        // extra: 1=shadow, 2=gshadow, 3=sudoers, 4=ssh_config, 5=pam_config
        const char *file_type;
        switch (event->extra) {
        case 1: file_type = "shadow"; break;
        case 2: file_type = "gshadow"; break;
        case 3: file_type = "sudoers"; break;
        case 4: file_type = "ssh_config"; break;
        case 5: file_type = "pam_config"; break;
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
    }

    int ret = fprintf(log_fp, "}\n");

    pthread_mutex_unlock(&log_mutex);

    if (!check_fprintf_result(ret))
        return -EIO;

    // Log to syslog if enabled (security events use LOG_WARNING)
    if (enable_syslog) {
        syslog(LOG_WARNING, "%s: pid=%u uid=%u comm=%s",
               event_type, event->pid, event->uid, event->comm);
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

void logger_cleanup(void)
{
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
}
