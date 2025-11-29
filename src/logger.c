// SPDX-License-Identifier: GPL-2.0
// Event logging implementation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "logger.h"
#include "userdb.h"
#include "filehash.h"

static FILE *log_fp = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool enable_resolve_usernames = false;
static bool enable_hash_binaries = false;

int logger_init(const char *log_file)
{
    log_fp = fopen(log_file, "a");
    if (!log_fp) {
        return -errno;
    }

    // Set line buffering
    setlinebuf(log_fp);

    return 0;
}

void logger_set_enrichment(bool resolve_usernames, bool hash_binaries)
{
    enable_resolve_usernames = resolve_usernames;
    enable_hash_binaries = hash_binaries;
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
                snprintf(dst + j, dst_size - j, "\\u%04x", c);
                j += 6;
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

    // Resolve username if enabled
    if (enable_resolve_usernames) {
        userdb_resolve(event->uid, username, sizeof(username));
        json_escape(username, username_escaped, sizeof(username_escaped));
    }

    pthread_mutex_lock(&log_mutex);

    fprintf(log_fp,
            "{\"timestamp\":\"%s\",\"type\":\"%s\",\"pid\":%u,\"ppid\":%u,"
            "\"uid\":%u",
            timestamp, event_type, event->pid, event->ppid,
            event->uid);

    if (enable_resolve_usernames) {
        fprintf(log_fp, ",\"username\":\"%s\"", username_escaped);
    }

    fprintf(log_fp, ",\"comm\":\"%s\"", comm_escaped);

    if (event->filename[0]) {
        json_escape(event->filename, filename_escaped, sizeof(filename_escaped));
        fprintf(log_fp, ",\"filename\":\"%s\"", filename_escaped);

        // Hash binary if enabled and this is an exec event
        if (enable_hash_binaries && event->type == EVENT_PROCESS_EXEC) {
            if (filehash_calculate(event->filename, sha256, sizeof(sha256))) {
                fprintf(log_fp, ",\"sha256\":\"%s\"", sha256);
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

    fprintf(log_fp, "}\n");

    pthread_mutex_unlock(&log_mutex);

    return 0;
}

int logger_log_file_event(const struct file_event *event)
{
    char timestamp[64];
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

    if (enable_resolve_usernames) {
        userdb_resolve(event->uid, username, sizeof(username));
        json_escape(username, username_escaped, sizeof(username_escaped));
    }

    pthread_mutex_lock(&log_mutex);

    fprintf(log_fp,
            "{\"timestamp\":\"%s\",\"type\":\"%s\",\"pid\":%u,\"uid\":%u",
            timestamp, event_type, event->pid, event->uid);

    if (enable_resolve_usernames) {
        fprintf(log_fp, ",\"username\":\"%s\"", username_escaped);
    }

    fprintf(log_fp, ",\"comm\":\"%s\",\"filename\":\"%s\",\"flags\":%u}\n",
            comm_escaped, filename_escaped, event->flags);

    pthread_mutex_unlock(&log_mutex);

    return 0;
}

int logger_log_network_event(const struct network_event *event)
{
    char timestamp[64];
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

    pthread_mutex_lock(&log_mutex);

    fprintf(log_fp,
            "{\"timestamp\":\"%s\",\"type\":\"%s\",\"pid\":%u,"
            "\"uid\":%u",
            timestamp, event_type, event->pid, event->uid);

    if (enable_resolve_usernames) {
        fprintf(log_fp, ",\"username\":\"%s\"", username_escaped);
    }

    fprintf(log_fp, ",\"comm\":\"%s\",\"saddr\":\"%s\","
            "\"daddr\":\"%s\",\"sport\":%u,\"dport\":%u}\n",
            comm_escaped, saddr_str, daddr_str,
            event->sport, event->dport);

    pthread_mutex_unlock(&log_mutex);

    return 0;
}

int logger_log_privilege_event(const struct privilege_event *event)
{
    char timestamp[64];
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

    if (enable_resolve_usernames) {
        userdb_resolve(event->old_uid, old_username, sizeof(old_username));
        userdb_resolve(event->new_uid, new_username, sizeof(new_username));
        json_escape(old_username, old_username_escaped, sizeof(old_username_escaped));
        json_escape(new_username, new_username_escaped, sizeof(new_username_escaped));
    }

    pthread_mutex_lock(&log_mutex);

    fprintf(log_fp,
            "{\"timestamp\":\"%s\",\"type\":\"%s\",\"pid\":%u,"
            "\"old_uid\":%u",
            timestamp, event_type, event->pid,
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

    if (event->target_comm[0]) {
        json_escape(event->target_comm, target_escaped, sizeof(target_escaped));
        fprintf(log_fp, ",\"target\":\"%s\"", target_escaped);
    }

    fprintf(log_fp, "}\n");

    pthread_mutex_unlock(&log_mutex);

    return 0;
}

void logger_cleanup(void)
{
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
}
