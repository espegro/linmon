// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// LinMon daemon - main entry point

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <sys/resource.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <grp.h>
#include <syslog.h>
#include <time.h>
#include <sys/utsname.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "logger.h"
#include "config.h"
#include "filter.h"
#include "userdb.h"
#include "filehash.h"
#include "pkgcache.h"
#include "procfs.h"
#include "authcheck.h"
#include "linmon.skel.h"
#include "../bpf/common.h"
#include <arpa/inet.h>
#include <linux/securebits.h>

// Ambient capability support (Linux >= 4.3)
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_RAISE 2
#endif

static volatile bool exiting = false;
static volatile bool reload_config = false;

static struct linmon_config global_config = {0};
static const char *config_path = "/etc/linmon/linmon.conf";

// Signal information for tamper detection logging
static volatile sig_atomic_t last_signal = 0;
static volatile pid_t signal_sender_pid = 0;
static volatile uid_t signal_sender_uid = 0;

// Integrity monitoring - daemon and config hashes
static char daemon_binary_path[PATH_MAX];
static char daemon_sha256[SHA256_HEX_LEN] = {0};
static char config_sha256[SHA256_HEX_LEN] = {0};
static time_t daemon_start_time = 0;

// Enhanced signal handler with sender information (tamper detection)
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

// Log daemon lifecycle event to both JSON and syslog with integrity info
static void log_daemon_event(const char *event_type, const char *message,
                              int sig, pid_t sender_pid, uid_t sender_uid,
                              const char *version, const char *daemon_hash,
                              const char *config_hash)
{
    char timestamp[64];
    struct timespec ts;
    struct tm tm_info;

    // Format timestamp
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm_info);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", &tm_info);
    snprintf(timestamp + strlen(timestamp), sizeof(timestamp) - strlen(timestamp),
             ".%03ldZ", ts.tv_nsec / 1000000);

    // Log to syslog (goes to journald on systemd systems)
    if (sig > 0) {
        syslog(LOG_WARNING, "%s: signal=%d sender_pid=%d sender_uid=%d "
                           "version=%s daemon_sha256=%s config_sha256=%s - %s",
               event_type, sig, (int)sender_pid, (int)sender_uid,
               version, daemon_hash, config_hash, message);
    } else {
        syslog(LOG_INFO, "%s: version=%s daemon_sha256=%s config_sha256=%s - %s",
               event_type, version, daemon_hash, config_hash, message);
    }

    // Also log to JSON if logger is initialized
    // Note: We use fprintf directly since logger may not have a daemon_event function
    FILE *log_fp = logger_get_fp();
    if (log_fp) {
        pthread_mutex_t *mutex = logger_get_mutex();
        if (mutex) pthread_mutex_lock(mutex);

        fprintf(log_fp, "{\"timestamp\":\"%s\",\"type\":\"%s\","
                       "\"version\":\"%s\",\"daemon_sha256\":\"%s\",\"config_sha256\":\"%s\"",
                timestamp, event_type, version, daemon_hash, config_hash);

        if (sig > 0) {
            const char *sig_name = (sig == SIGTERM) ? "SIGTERM" :
                                   (sig == SIGINT) ? "SIGINT" :
                                   (sig == SIGHUP) ? "SIGHUP" : "UNKNOWN";
            fprintf(log_fp, ",\"signal\":\"%s\",\"signal_num\":%d", sig_name, sig);
            fprintf(log_fp, ",\"sender_pid\":%d,\"sender_uid\":%d",
                    (int)sender_pid, (int)sender_uid);
        }
        fprintf(log_fp, ",\"message\":\"%s\"}\n", message);
        fflush(log_fp);

        if (mutex) pthread_mutex_unlock(mutex);
    }
}

// Log periodic checkpoint with integrity info
static void log_checkpoint_to_syslog(void)
{
    uint64_t seq = logger_get_sequence();
    unsigned long events = logger_get_event_count();
    long uptime = time(NULL) - daemon_start_time;

    // Recalculate config hash (in case it changed on disk without SIGHUP)
    char current_config_sha256[SHA256_HEX_LEN];
    if (!filehash_calculate(config_path, current_config_sha256, sizeof(current_config_sha256))) {
        strncpy(current_config_sha256, "error", sizeof(current_config_sha256));
        current_config_sha256[sizeof(current_config_sha256) - 1] = '\0';
    }

    // Log to syslog
    syslog(LOG_INFO, "checkpoint: version=%s seq=%lu events=%lu uptime=%ld "
                     "daemon_sha256=%s config_sha256=%s",
           LINMON_VERSION, seq, events, uptime,
           daemon_sha256, current_config_sha256);

    // Also log to JSON
    log_daemon_event("daemon_checkpoint", "Periodic integrity checkpoint",
                    0, 0, 0, LINMON_VERSION, daemon_sha256, current_config_sha256);
}

static void print_usage(const char *progname)
{
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("\nOptions:\n");
    printf("  -c, --config PATH          Configuration file path (default: /etc/linmon/linmon.conf)\n");
    printf("  -h, --help                 Show this help message\n");
    printf("  -v, --version              Show version information\n");
    printf("\nConfiguration overrides (override config file):\n");
    printf("  --resolve-usernames BOOL   Enable/disable username resolution (true/false)\n");
    printf("  --hash-binaries BOOL       Enable/disable binary hashing (true/false)\n");
    printf("  --monitor-files BOOL       Enable/disable file monitoring (true/false)\n");
    printf("  --monitor-network BOOL     Enable/disable network monitoring (true/false)\n");
    printf("\nSignals:\n");
    printf("  SIGINT/SIGTERM             Graceful shutdown\n");
    printf("  SIGHUP                     Reload configuration\n");
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                          va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

static int prepare_capabilities(void)
{
    cap_t caps;
    cap_value_t cap_values[1] = { CAP_SYS_PTRACE };
    int ret;

    // Prevent capability clearing on setuid()
    // SECBIT_KEEP_CAPS: Keep caps when switching to non-root UID
    // SECBIT_NO_SETUID_FIXUP: Don't clear PERMITTED/EFFECTIVE on setuid
    ret = prctl(PR_SET_SECUREBITS,
                SECBIT_KEEP_CAPS | SECBIT_KEEP_CAPS_LOCKED |
                SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED);
    if (ret) {
        fprintf(stderr, "Failed to set securebits: %s\n", strerror(errno));
        return -1;
    }

    // Get current capabilities
    caps = cap_get_proc();
    if (!caps) {
        fprintf(stderr, "Failed to get capabilities: %s\n", strerror(errno));
        return -1;
    }

    // Set CAP_SYS_PTRACE in PERMITTED set (required for ambient)
    ret = cap_set_flag(caps, CAP_PERMITTED, 1, cap_values, CAP_SET);
    if (ret) {
        fprintf(stderr, "Failed to set permitted capabilities: %s\n", strerror(errno));
        cap_free(caps);
        return -1;
    }

    // Set CAP_SYS_PTRACE in EFFECTIVE set (required for ambient)
    ret = cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_values, CAP_SET);
    if (ret) {
        fprintf(stderr, "Failed to set effective capabilities: %s\n", strerror(errno));
        cap_free(caps);
        return -1;
    }

    // Set CAP_SYS_PTRACE in INHERITABLE set (required for ambient)
    ret = cap_set_flag(caps, CAP_INHERITABLE, 1, cap_values, CAP_SET);
    if (ret) {
        fprintf(stderr, "Failed to set inheritable capabilities: %s\n", strerror(errno));
        cap_free(caps);
        return -1;
    }

    // Apply the capability set
    ret = cap_set_proc(caps);
    if (ret) {
        fprintf(stderr, "Failed to set capabilities: %s\n", strerror(errno));
        cap_free(caps);
        return -1;
    }

    cap_free(caps);

    // Set ambient capability so CAP_SYS_PTRACE persists across UID change
    // Requires: CAP in PERMITTED, EFFECTIVE, and INHERITABLE sets (done above)
    // Requires: SECBIT_NO_SETUID_FIXUP to prevent clearing on setuid
    // Kernel requirement: >= 4.3
    ret = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_PTRACE, 0, 0);
    if (ret) {
        fprintf(stderr, "Failed to set ambient capability: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const __u32 *type_ptr = data;
    __u32 type;

    (void)ctx;

    if (data_sz < sizeof(__u32))
        return 0;

    type = *type_ptr;

    // Route to appropriate logger based on event type
    switch (type) {
    case EVENT_PROCESS_EXEC:
    case EVENT_PROCESS_EXIT: {
        // Check if process monitoring is enabled
        if (!global_config.monitor_processes)
            return 0;

        if (data_sz < sizeof(struct process_event)) {
            fprintf(stderr, "Invalid process event size: %zu\n", data_sz);
            return 0;
        }

        // Create a copy of the event since ring buffer data is read-only
        struct process_event event_copy;
        memcpy(&event_copy, data, sizeof(event_copy));
        struct process_event *e = &event_copy;

        // Check if exit events should be logged
        if (e->type == EVENT_PROCESS_EXIT && !global_config.monitor_process_exit)
            return 0;

        // Check if process should be logged
        if (!filter_should_log_process(e->comm))
            return 0;

        // Capture command line if enabled and this is an exec event
        if (global_config.capture_cmdline && e->type == EVENT_PROCESS_EXEC) {
            // Read from /proc/<pid>/cmdline (process may have exited, that's OK)
            procfs_read_cmdline(e->pid, e->cmdline, sizeof(e->cmdline));
        }

        // Redact sensitive information if enabled
        if (global_config.redact_sensitive && e->cmdline[0] != '\0')
            filter_redact_cmdline(e->cmdline, sizeof(e->cmdline));

        logger_log_process_event(e);
        break;
    }

    case EVENT_FILE_OPEN:
    case EVENT_FILE_CREATE:
    case EVENT_FILE_DELETE:
    case EVENT_FILE_MODIFY: {
        // Check if file monitoring is enabled
        if (!global_config.monitor_files)
            return 0;

        if (data_sz < sizeof(struct file_event)) {
            fprintf(stderr, "Invalid file event size: %zu\n", data_sz);
            return 0;
        }
        struct file_event *e = data;

        if (!filter_should_log_process(e->comm))
            return 0;

        // Check if file path should be logged
        if (!filter_should_log_file(e->filename))
            return 0;

        logger_log_file_event(e);
        break;
    }

    case EVENT_NET_CONNECT_TCP:
    case EVENT_NET_ACCEPT_TCP: {
        // Check if TCP monitoring is enabled
        if (!global_config.monitor_tcp)
            return 0;

        if (data_sz < sizeof(struct network_event)) {
            fprintf(stderr, "Invalid network event size: %zu\n", data_sz);
            return 0;
        }
        struct network_event *e = data;

        if (!filter_should_log_process(e->comm))
            return 0;

        logger_log_network_event(e);
        break;
    }

    case EVENT_NET_SEND_UDP: {
        // Check if UDP monitoring is enabled
        if (!global_config.monitor_udp)
            return 0;

        if (data_sz < sizeof(struct network_event)) {
            fprintf(stderr, "Invalid network event size: %zu\n", data_sz);
            return 0;
        }
        struct network_event *e = data;

        if (!filter_should_log_process(e->comm))
            return 0;

        logger_log_network_event(e);
        break;
    }

    case EVENT_NET_VSOCK_CONNECT: {
        // Check if vsock monitoring is enabled
        if (!global_config.monitor_vsock)
            return 0;

        if (data_sz < sizeof(struct network_event)) {
            fprintf(stderr, "Invalid network event size: %zu\n", data_sz);
            return 0;
        }
        struct network_event *e = data;

        if (!filter_should_log_process(e->comm))
            return 0;

        logger_log_network_event(e);
        break;
    }

    case EVENT_PRIV_SETUID:
    case EVENT_PRIV_SETGID:
    case EVENT_PRIV_SUDO: {
        if (data_sz < sizeof(struct privilege_event)) {
            fprintf(stderr, "Invalid privilege event size: %zu\n", data_sz);
            return 0;
        }
        struct privilege_event *e = data;

        // Apply process filtering to prevent privilege event flooding
        if (!filter_should_log_process(e->comm))
            return 0;

        logger_log_privilege_event(e);
        break;
    }

    // Security monitoring events (MITRE ATT&CK detection)
    case EVENT_SECURITY_PTRACE:
    case EVENT_SECURITY_MODULE:
    case EVENT_SECURITY_MEMFD:
    case EVENT_SECURITY_BIND:
    case EVENT_SECURITY_UNSHARE:
    case EVENT_SECURITY_EXECVEAT:
    case EVENT_SECURITY_BPF:
    case EVENT_SECURITY_CRED_READ:
    case EVENT_SECURITY_LDPRELOAD:
    case EVENT_SECURITY_SUID:
    case EVENT_SECURITY_CRED_WRITE:
    case EVENT_SECURITY_LOG_TAMPER:
    case EVENT_RAW_DISK_ACCESS: {
        // Check respective config flags
        if (type == EVENT_SECURITY_PTRACE && !global_config.monitor_ptrace)
            return 0;
        if (type == EVENT_SECURITY_MODULE && !global_config.monitor_modules)
            return 0;
        if (type == EVENT_SECURITY_MEMFD && !global_config.monitor_memfd)
            return 0;
        if (type == EVENT_SECURITY_BIND && !global_config.monitor_bind)
            return 0;
        if (type == EVENT_SECURITY_UNSHARE && !global_config.monitor_unshare)
            return 0;
        if (type == EVENT_SECURITY_EXECVEAT && !global_config.monitor_execveat)
            return 0;
        if (type == EVENT_SECURITY_BPF && !global_config.monitor_bpf)
            return 0;
        if (type == EVENT_SECURITY_CRED_READ && !global_config.monitor_cred_read)
            return 0;
        if (type == EVENT_SECURITY_LDPRELOAD && !global_config.monitor_ldpreload)
            return 0;
        if (type == EVENT_SECURITY_SUID && !global_config.monitor_suid)
            return 0;
        if (type == EVENT_SECURITY_CRED_WRITE && !global_config.monitor_cred_write)
            return 0;
        if (type == EVENT_SECURITY_LOG_TAMPER && !global_config.monitor_log_tamper)
            return 0;
        if (type == EVENT_RAW_DISK_ACCESS && !global_config.monitor_raw_disk_access)
            return 0;

        if (data_sz < sizeof(struct security_event)) {
            fprintf(stderr, "Invalid security event size: %zu\n", data_sz);
            return 0;
        }
        struct security_event *e = data;

        // Apply process filtering
        if (!filter_should_log_process(e->comm))
            return 0;

        logger_log_security_event(e);
        break;
    }

    case EVENT_SECURITY_PERSISTENCE: {
        if (!global_config.monitor_persistence)
            return 0;

        if (data_sz < sizeof(struct persistence_event)) {
            fprintf(stderr, "Invalid persistence event size: %zu\n", data_sz);
            return 0;
        }
        struct persistence_event *e = data;

        // Apply process filtering
        if (!filter_should_log_process(e->comm))
            return 0;

        logger_log_persistence_event(e);
        break;
    }

    default:
        fprintf(stderr, "Unknown event type: %u\n", type);
        break;
    }

    return 0;
}

static int update_bpf_config(int config_map_fd, const struct linmon_config *config)
{
    struct {
        __u32 min_uid;
        __u32 max_uid;
        __u8 capture_cmdline;
        __u8 require_tty;
        __u8 ignore_threads;
    } bpf_config = {
        .min_uid = config->min_uid,
        .max_uid = config->max_uid,
        .capture_cmdline = config->capture_cmdline ? 1 : 0,
        .require_tty = config->require_tty ? 1 : 0,
        .ignore_threads = config->ignore_threads ? 1 : 0,
    };
    __u32 key = 0;

    return bpf_map_update_elem(config_map_fd, &key, &bpf_config, BPF_ANY);
}

// Parse CIDR notation (e.g., "10.0.0.0/8") into network address and mask
static int parse_cidr(const char *cidr_str, struct network_cidr *out)
{
    char ip_str[32];
    char *slash;
    int prefix_len;
    struct in_addr addr;
    __u32 mask;

    // Make a copy to tokenize
    strncpy(ip_str, cidr_str, sizeof(ip_str) - 1);
    ip_str[sizeof(ip_str) - 1] = '\0';

    // Find the slash
    slash = strchr(ip_str, '/');
    if (!slash) {
        fprintf(stderr, "Invalid CIDR notation (missing /): %s\n", cidr_str);
        return -1;
    }

    *slash = '\0';

    // Parse prefix length with proper error handling
    char *endptr;
    long prefix_len_long = strtol(slash + 1, &endptr, 10);
    if (*endptr != '\0' || prefix_len_long < 0 || prefix_len_long > 32) {
        fprintf(stderr, "Invalid CIDR prefix length: %s (must be 0-32)\n", slash + 1);
        return -1;
    }
    prefix_len = (int)prefix_len_long;

    // Parse IP address
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return -1;
    }

    // Calculate mask (in network byte order, then convert to host byte order)
    if (prefix_len == 0) {
        mask = 0;
    } else {
        mask = htonl(~0U << (32 - prefix_len));
    }

    // Store in host byte order for eBPF comparison
    out->addr = ntohl(addr.s_addr) & ntohl(mask);
    out->mask = ntohl(mask);

    return 0;
}

// Update network CIDR filtering map from config
static int update_network_filters(int map_fd, const struct linmon_config *config)
{
    char *cidr_list, *cidr_token, *saveptr;
    struct network_cidr cidr;
    __u32 index = 0;
    int err;

    // Clear existing entries by creating a new map
    // (BPF maps can't be cleared, so we just overwrite)

    if (!config->ignore_networks || strlen(config->ignore_networks) == 0)
        return 0;  // No networks to filter

    // Make a copy of the string for tokenization
    cidr_list = strdup(config->ignore_networks);
    if (!cidr_list)
        return -ENOMEM;

    // Parse comma-separated CIDR blocks
    cidr_token = strtok_r(cidr_list, ",", &saveptr);
    while (cidr_token && index < 16) {  // Max 16 CIDR blocks (BPF map size limit)
        // Trim whitespace
        while (*cidr_token == ' ' || *cidr_token == '\t')
            cidr_token++;

        if (strlen(cidr_token) == 0) {
            cidr_token = strtok_r(NULL, ",", &saveptr);
            continue;
        }

        // Parse CIDR
        err = parse_cidr(cidr_token, &cidr);
        if (err) {
            fprintf(stderr, "Skipping invalid CIDR: %s\n", cidr_token);
            cidr_token = strtok_r(NULL, ",", &saveptr);
            continue;
        }

        // Insert into BPF map
        err = bpf_map_update_elem(map_fd, &index, &cidr, BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to update CIDR map at index %u: %d\n", index, err);
            free(cidr_list);
            return err;
        }

        index++;
        cidr_token = strtok_r(NULL, ",", &saveptr);
    }

    free(cidr_list);

    if (index > 0) {
        printf("  Network CIDR filtering: %u block(s) loaded\n", index);
    }

    // Warn if user tried to configure more than the limit
    if (cidr_token != NULL) {
        fprintf(stderr, "Warning: Maximum 16 CIDR blocks supported. Additional entries ignored.\n");
    }

    return 0;
}

// Smart BPF program attachment with fallback
// Tries tracepoint first, falls back to kprobe if tracepoint is blocked (RHEL 9)
static struct bpf_link *attach_prog_with_fallback(
    struct bpf_program *tp_prog,  // Tracepoint version
    struct bpf_program *kp_prog,  // Kprobe version (fallback)
    const char *name)              // Program name for logging
{
    struct bpf_link *link = NULL;
    int err;

    // Try tracepoint first (preferred - lower overhead)
    if (tp_prog) {
        link = bpf_program__attach(tp_prog);
        err = libbpf_get_error(link);

        if (!err) {
            // Success!
            printf("  ✓ %s (tracepoint)\n", name);
            return link;
        }

        // If error is not EPERM, it's a real error
        if (err != -EPERM && err != -EACCES) {
            fprintf(stderr, "  ✗ %s (tracepoint): %s\n", name, strerror(-err));
            return NULL;
        }

        // EPERM means tracepoint is blocked, try kprobe
        printf("  ! %s: tracepoint blocked, trying kprobe...\n", name);
        link = NULL;  // Clear failed link
    }

    // Try kprobe fallback
    if (kp_prog) {
        link = bpf_program__attach(kp_prog);
        err = libbpf_get_error(link);

        if (!err) {
            printf("  ✓ %s (kprobe fallback)\n", name);
            return link;
        }

        fprintf(stderr, "  ✗ %s (kprobe): %s\n", name, strerror(-err));
        return NULL;
    }

    fprintf(stderr, "  ✗ %s: no fallback available\n", name);
    return NULL;
}

// Manual BPF program attachment with smart fallback for syscall monitors
static int attach_bpf_programs(struct linmon_bpf *skel)
{
    struct bpf_link *link;
    int attached_count = 0;
    int failed_count = 0;

    printf("Attaching BPF programs...\n");

    // Process monitoring (always available - uses sched tracepoints, not syscall)
    link = bpf_program__attach(skel->progs.handle_exec);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "✗ CRITICAL: Failed to attach process exec monitor\n");
        return -1;
    }
    printf("  ✓ Process exec monitoring\n");
    attached_count++;

    link = bpf_program__attach(skel->progs.handle_exit);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "✗ CRITICAL: Failed to attach process exit monitor\n");
        return -1;
    }
    printf("  ✓ Process exit monitoring\n");
    attached_count++;

    // File monitoring (with fallback)
    link = attach_prog_with_fallback(
        skel->progs.handle_openat_tp,
        skel->progs.handle_openat_kp,
        "File open/create monitoring");
    if (!link) failed_count++; else attached_count++;

    link = attach_prog_with_fallback(
        skel->progs.handle_unlinkat_tp,
        skel->progs.handle_unlinkat_kp,
        "File delete monitoring");
    if (!link) failed_count++; else attached_count++;

    // Network monitoring (kprobes - always available)
    link = bpf_program__attach(skel->progs.tcp_connect_enter);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "  ✗ TCP connect monitoring failed\n");
        failed_count++;
    } else {
        printf("  ✓ TCP connect monitoring\n");
        attached_count++;
    }

    link = bpf_program__attach(skel->progs.tcp_v4_connect_enter);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "  ✗ TCP v4 connect monitoring failed\n");
        failed_count++;
    } else {
        printf("  ✓ TCP v4 connect monitoring\n");
        attached_count++;
    }

    link = bpf_program__attach(skel->progs.inet_accept_exit);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "  ✗ TCP accept monitoring failed\n");
        failed_count++;
    } else {
        printf("  ✓ TCP accept monitoring\n");
        attached_count++;
    }

    link = bpf_program__attach(skel->progs.udp_sendmsg_enter);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "  ✗ UDP send monitoring failed\n");
        failed_count++;
    } else {
        printf("  ✓ UDP send monitoring\n");
        attached_count++;
    }

    link = bpf_program__attach(skel->progs.udpv6_sendmsg_enter);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "  ✗ UDPv6 send monitoring failed\n");
        failed_count++;
    } else {
        printf("  ✓ UDPv6 send monitoring\n");
        attached_count++;
    }

    link = bpf_program__attach(skel->progs.vsock_connect_enter);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "  ✗ vsock connect monitoring failed\n");
        failed_count++;
    } else {
        printf("  ✓ vsock (VM/container) connect monitoring\n");
        attached_count++;
    }

    // Privilege monitoring (with fallback)
    link = attach_prog_with_fallback(
        skel->progs.handle_setuid_tp,
        skel->progs.handle_setuid_kp,
        "Setuid monitoring");
    if (!link) failed_count++; else attached_count++;

    link = attach_prog_with_fallback(
        skel->progs.handle_setgid_tp,
        skel->progs.handle_setgid_kp,
        "Setgid monitoring");
    if (!link) failed_count++; else attached_count++;

    // Privilege escalation detection (sudo/su/pkexec - always available via exec monitoring)
    link = bpf_program__attach(skel->progs.handle_privilege_exec);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "  ✗ Privilege escalation detection failed\n");
        failed_count++;
    } else {
        printf("  ✓ Sudo/su/pkexec detection\n");
        attached_count++;
    }

    // Security monitoring - ptrace (T1055 Process Injection)
    link = attach_prog_with_fallback(
        skel->progs.handle_ptrace_tp,
        skel->progs.handle_ptrace_kp,
        "Ptrace monitoring (T1055)");
    if (!link) failed_count++; else attached_count++;

    // Security monitoring - finit_module (T1547.006 Kernel Modules)
    link = attach_prog_with_fallback(
        skel->progs.handle_finit_module_tp,
        skel->progs.handle_finit_module_kp,
        "Module loading (T1547.006)");
    if (!link) failed_count++; else attached_count++;

    // Security monitoring - init_module (T1547.006 Kernel Modules - legacy)
    link = attach_prog_with_fallback(
        skel->progs.handle_init_module_tp,
        skel->progs.handle_init_module_kp,
        "Legacy module loading (T1547.006)");
    if (!link) failed_count++; else attached_count++;

    // Security monitoring - memfd_create (T1620 Fileless Malware)
    link = attach_prog_with_fallback(
        skel->progs.handle_memfd_create_tp,
        skel->progs.handle_memfd_create_kp,
        "Memfd monitoring (T1620)");
    if (!link) failed_count++; else attached_count++;

    // Security monitoring - bind (T1571 Bind Shell / C2)
    link = attach_prog_with_fallback(
        skel->progs.handle_bind_tp,
        skel->progs.handle_bind_kp,
        "Bind monitoring (T1571)");
    if (!link) failed_count++; else attached_count++;

    // Security monitoring - unshare (T1611 Container Escape)
    link = attach_prog_with_fallback(
        skel->progs.handle_unshare_tp,
        skel->progs.handle_unshare_kp,
        "Unshare monitoring (T1611)");
    if (!link) failed_count++; else attached_count++;

    // Security monitoring - execveat (T1620 Fileless Execution)
    link = attach_prog_with_fallback(
        skel->progs.handle_execveat_tp,
        skel->progs.handle_execveat_kp,
        "Execveat monitoring (T1620)");
    if (!link) failed_count++; else attached_count++;

    // Security monitoring - bpf (T1014 eBPF Rootkit)
    link = attach_prog_with_fallback(
        skel->progs.handle_bpf_tp,
        skel->progs.handle_bpf_kp,
        "BPF monitoring (T1014)");
    if (!link) failed_count++; else attached_count++;

    // Security monitoring - credential read and LD_PRELOAD (T1003.008, T1574.006)
    link = attach_prog_with_fallback(
        skel->progs.handle_security_openat_tp,
        skel->progs.handle_security_openat_kp,
        "Credential/LDPreload monitoring (T1003.008/T1574.006)");
    if (!link) failed_count++; else attached_count++;

    // Security monitoring - SUID/SGID manipulation (T1548.001)
    link = attach_prog_with_fallback(
        skel->progs.handle_fchmodat_tp,
        skel->progs.handle_fchmodat_kp,
        "SUID/SGID monitoring (T1548.001)");
    if (!link) failed_count++; else attached_count++;

    // Security monitoring - persistence mechanisms (T1053, T1547)
    link = attach_prog_with_fallback(
        skel->progs.handle_persistence_openat_tp,
        skel->progs.handle_persistence_openat_kp,
        "Persistence monitoring (T1053, T1547)");
    if (!link) failed_count++; else attached_count++;

    printf("\nAttachment summary: %d programs attached", attached_count);
    if (failed_count > 0) {
        printf(" (%d failed - some features may be unavailable)\n", failed_count);
    } else {
        printf(" (all features available)\n");
    }

    // We require at least process and network monitoring to work
    if (attached_count < 4) {
        fprintf(stderr, "\nCRITICAL: Too few monitors attached. Cannot continue.\n");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct linmon_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;
    int opt;

    static struct option long_options[] = {
        {"config",  required_argument, 0, 'c'},
        {"help",    no_argument,       0, 'h'},
        {"version", no_argument,       0, 'v'},
        {0, 0, 0, 0}
    };

    // Parse command line arguments
    while ((opt = getopt_long(argc, argv, "c:hv", long_options, NULL)) != -1) {
        switch (opt) {
        case 'c':
            config_path = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        case 'v':
            printf("LinMon version %s\n", LINMON_VERSION);
            printf("eBPF-based system monitoring for Linux\n");
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    // Set up signal handlers with sigaction (captures sender info for tamper detection)
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sig_handler_info;
    sa.sa_flags = SA_SIGINFO;  // Use sa_sigaction instead of sa_handler
    sigemptyset(&sa.sa_mask);

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    // Initialize syslog for daemon lifecycle events (goes to journald on systemd)
    openlog("linmond", LOG_PID | LOG_CONS, LOG_DAEMON);

    // Set up libbpf logging
    libbpf_set_print(libbpf_print_fn);

    // Bump RLIMIT_MEMLOCK to allow BPF programs to use more memory
    err = bump_memlock_rlimit();
    if (err) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit: %s\n",
                strerror(errno));
        fprintf(stderr, "Try running with sudo\n");
        return 1;
    }

    // Load configuration
    err = load_config(&global_config, config_path);
    if (err && err != -ENOENT) {
        fprintf(stderr, "Failed to load configuration: %s\n", strerror(-err));
        return 1;
    }

    // Initialize logger
    err = logger_init(global_config.log_file ? global_config.log_file :
                     "/var/log/linmon/events.json");
    if (err) {
        fprintf(stderr, "Failed to initialize logger: %s\n", strerror(-err));
        return 1;
    }

    // Initialize user database
    userdb_init();

    // Initialize file hash cache if enabled
    if (global_config.hash_binaries) {
        filehash_init(global_config.hash_cache_file,
                      global_config.hash_cache_size);
    }

    // Initialize package cache if enabled
    if (global_config.verify_packages) {
        pkgcache_init(global_config.pkg_cache_file,
                      global_config.pkg_cache_size);
    }

    // Initialize authentication integrity monitoring
    if (global_config.monitor_auth_integrity) {
        authcheck_init(global_config.verify_packages);
    }

    // Configure logger enrichment options
    logger_set_enrichment(global_config.resolve_usernames,
                         global_config.hash_binaries,
                         global_config.verify_packages,
                         global_config.capture_container_metadata);

    // Configure syslog output for all events
    logger_set_syslog(global_config.log_to_syslog);

    // Configure built-in log rotation
    const char *log_path = global_config.log_file ? global_config.log_file :
                           "/var/log/linmon/events.json";
    logger_set_rotation(log_path, global_config.log_rotate,
                        global_config.log_rotate_size,
                        global_config.log_rotate_count);

    printf("LinMon starting...\n");
    printf("Configuration:\n");
    printf("  UID range: %u-%u (0=unlimited)\n",
           global_config.min_uid, global_config.max_uid);
    printf("  Require TTY: %s\n", global_config.require_tty ? "yes (terminal only)" : "no (all sessions)");
    printf("  Processes: %s\n", global_config.monitor_processes ? "enabled" : "disabled");
    printf("  Files: %s\n", global_config.monitor_files ? "enabled" : "disabled");
    printf("  TCP: %s\n", global_config.monitor_tcp ? "enabled" : "disabled");
    printf("  UDP: %s\n", global_config.monitor_udp ? "enabled" : "disabled");
    printf("  Redact sensitive: %s\n", global_config.redact_sensitive ? "yes" : "no");
    printf("  Resolve usernames: %s\n", global_config.resolve_usernames ? "yes" : "no");
    printf("  Hash binaries: %s\n", global_config.hash_binaries ? "yes" : "no");
    printf("  Syslog output: %s\n", global_config.log_to_syslog ? "yes (all events)" : "no (daemon events only)");
    if (global_config.log_rotate) {
        printf("  Log rotation: enabled (%luMB, keep %d files)\n",
               global_config.log_rotate_size / (1024 * 1024),
               global_config.log_rotate_count);
    } else {
        printf("  Log rotation: disabled (use external logrotate)\n");
    }
    printf("  Security monitoring:\n");
    printf("    ptrace (T1055): %s\n", global_config.monitor_ptrace ? "enabled" : "disabled");
    printf("    modules (T1547.006): %s\n", global_config.monitor_modules ? "enabled" : "disabled");
    printf("    memfd (T1620): %s\n", global_config.monitor_memfd ? "enabled" : "disabled");
    printf("    bind (T1571): %s\n", global_config.monitor_bind ? "enabled" : "disabled");
    printf("    unshare (T1611): %s\n", global_config.monitor_unshare ? "enabled" : "disabled");
    printf("    execveat (T1620): %s\n", global_config.monitor_execveat ? "enabled" : "disabled");
    printf("    bpf (T1014): %s\n", global_config.monitor_bpf ? "enabled" : "disabled");
    printf("    cred_read (T1003.008): %s\n", global_config.monitor_cred_read ? "enabled" : "disabled");
    printf("    ldpreload (T1574.006): %s\n", global_config.monitor_ldpreload ? "enabled" : "disabled");

    // Initialize filter
    filter_init(&global_config);

    // Load and open BPF application
    // CRITICAL SECURITY CHECKPOINT: If this fails, it may indicate:
    // 1. Kernel rootkit blocking bpf() syscall (e.g., Singularity)
    // 2. Missing kernel BTF support
    // 3. Insufficient privileges
    skel = linmon_bpf__open_and_load();
    if (!skel) {
        // Get error details
        int bpf_errno = errno;
        const char *error_msg = strerror(bpf_errno);

        // CRITICAL: Log to syslog IMMEDIATELY (survives daemon exit)
        // This ensures we have persistent evidence of BPF load failures
        syslog(LOG_CRIT,
               "CRITICAL: Failed to load BPF programs: %s (errno=%d). "
               "This may indicate kernel rootkit interference (e.g., Singularity rootkit blocking bpf() syscall). "
               "LinMon cannot start without BPF support. "
               "Verify: 1) Kernel version >= 5.8, 2) BTF enabled (/sys/kernel/btf/vmlinux exists), "
               "3) No rootkit blocking bpf() syscall, 4) Sufficient capabilities (CAP_BPF, CAP_PERFMON). "
               "Check dmesg for kernel messages.",
               error_msg, bpf_errno);

        // Also log to stderr for systemd journal (visible in journalctl)
        fprintf(stderr, "\n");
        fprintf(stderr, "╔═══════════════════════════════════════════════════════════════╗\n");
        fprintf(stderr, "║  CRITICAL: LinMon BPF Program Loading FAILED                 ║\n");
        fprintf(stderr, "╚═══════════════════════════════════════════════════════════════╝\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Error: %s (errno=%d)\n", error_msg, bpf_errno);
        fprintf(stderr, "\n");
        fprintf(stderr, "This failure may indicate:\n");
        fprintf(stderr, "  1. 🚨 KERNEL ROOTKIT blocking bpf() syscall\n");
        fprintf(stderr, "     → Singularity-type attack in progress\n");
        fprintf(stderr, "     → Check: dmesg | grep -iE '(singularity|rootkit|module)'\n");
        fprintf(stderr, "     → Check: lsmod | grep -iE '(singularity|rootkit)'\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "  2. Missing kernel BTF (BPF Type Format) support\n");
        fprintf(stderr, "     → Check: ls -l /sys/kernel/btf/vmlinux\n");
        fprintf(stderr, "     → If missing, rebuild kernel with CONFIG_DEBUG_INFO_BTF=y\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "  3. Insufficient privileges\n");
        fprintf(stderr, "     → LinMon requires: CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN\n");
        fprintf(stderr, "     → Check: getcap /usr/local/sbin/linmond\n");
        fprintf(stderr, "     → Running as root? Check: id -u\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "  4. Kernel version too old\n");
        fprintf(stderr, "     → LinMon requires kernel >= 5.8 for CO-RE support\n");
        fprintf(stderr, "     → Check: uname -r\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "For rootkit investigation:\n");
        fprintf(stderr, "  sudo dmesg | tail -100\n");
        fprintf(stderr, "  sudo lsmod | head -20\n");
        fprintf(stderr, "  sudo journalctl -u linmond --since '10 minutes ago'\n");
        fprintf(stderr, "\n");

        // Create persistent alert file (forensic evidence, survives daemon exit)
        // This file can be checked by monitoring systems, SIEM, or manual investigation
        const char *alert_file = "/var/log/linmon/CRITICAL_BPF_LOAD_FAILED";
        FILE *alert_fp = fopen(alert_file, "w");
        if (alert_fp) {
            time_t now = time(NULL);
            char *time_str = ctime(&now);
            char hostname[256];
            struct utsname uname_buf;

            // Get hostname
            if (gethostname(hostname, sizeof(hostname)) != 0) {
                strncpy(hostname, "unknown", sizeof(hostname));
            }
            hostname[sizeof(hostname) - 1] = '\0';

            // Get kernel version
            if (uname(&uname_buf) != 0) {
                strncpy(uname_buf.release, "unknown", sizeof(uname_buf.release));
            }

            fprintf(alert_fp, "LinMon BPF Loading Failed\n");
            fprintf(alert_fp, "========================\n");
            fprintf(alert_fp, "Timestamp: %s", time_str); // ctime includes \n
            fprintf(alert_fp, "Error: %s (errno=%d)\n", error_msg, bpf_errno);
            fprintf(alert_fp, "Hostname: %s\n", hostname);
            fprintf(alert_fp, "Kernel: %s\n", uname_buf.release);
            fprintf(alert_fp, "\n");
            fprintf(alert_fp, "POSSIBLE ROOTKIT INTERFERENCE DETECTED\n");
            fprintf(alert_fp, "\n");
            fprintf(alert_fp, "Investigation Steps:\n");
            fprintf(alert_fp, "1. Check for known rootkits:\n");
            fprintf(alert_fp, "   dmesg | grep -iE '(singularity|rootkit|lkrg|module.*blocked)'\n");
            fprintf(alert_fp, "\n");
            fprintf(alert_fp, "2. Check loaded kernel modules:\n");
            fprintf(alert_fp, "   lsmod | head -20\n");
            fprintf(alert_fp, "\n");
            fprintf(alert_fp, "3. Check for hidden modules (if LKRG installed):\n");
            fprintf(alert_fp, "   dmesg | grep LKRG\n");
            fprintf(alert_fp, "\n");
            fprintf(alert_fp, "4. Check system call blocking:\n");
            fprintf(alert_fp, "   strace -e bpf bpftool prog list 2>&1 | head\n");
            fprintf(alert_fp, "\n");
            fprintf(alert_fp, "5. Verify kernel configuration:\n");
            fprintf(alert_fp, "   ls -l /sys/kernel/btf/vmlinux\n");
            fprintf(alert_fp, "   grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)\n");
            fprintf(alert_fp, "\n");
            fclose(alert_fp);

            // Log that we created the alert file
            syslog(LOG_CRIT, "Created alert file: %s", alert_file);
        } else {
            // Even if we can't create alert file, log the attempt
            syslog(LOG_ERR, "Failed to create alert file %s: %s", alert_file, strerror(errno));
        }

        err = -1;
        goto cleanup;
    }

    // SUCCESS: BPF programs loaded successfully
    // Log this for tamper detection - absence of this log may indicate manipulation
    syslog(LOG_INFO, "BPF programs loaded successfully (no interference detected)");

    // Update config map
    err = update_bpf_config(bpf_map__fd(skel->maps.config_map), &global_config);
    if (err) {
        fprintf(stderr, "Failed to update BPF config map: %d\n", err);
        goto cleanup;
    }

    // Update network CIDR filtering
    err = update_network_filters(bpf_map__fd(skel->maps.ignore_networks_map), &global_config);
    if (err) {
        fprintf(stderr, "Failed to update network filters: %d\n", err);
        goto cleanup;
    }

    // Attach all BPF programs with smart fallback (tracepoint → kprobe for RHEL 9)
    err = attach_bpf_programs(skel);
    if (err) {
        fprintf(stderr, "Failed to attach LinMon BPF programs: %d\n", err);
        goto cleanup;
    }

    // Check if /proc is accessible (detect hidepid mount option)
    // We test /proc/1/cmdline - if this fails, /proc/<pid>/exe will also fail
    // This affects process_name field availability for network/privilege/security events
    FILE *proc_test = fopen("/proc/1/cmdline", "r");
    if (!proc_test) {
        fprintf(stderr, "Warning: Cannot read /proc/1/cmdline - process_name field may be unavailable\n");
        fprintf(stderr, "  This can happen if /proc is mounted with hidepid option\n");
        fprintf(stderr, "  Process exec events will still have process_name (from eBPF)\n");
    } else {
        fclose(proc_test);
    }

    // Calculate daemon binary hash (for tamper detection)
    // Must be done before privilege dropping (need CAP_DAC_READ_SEARCH to read executable)
    if (realpath(argv[0], daemon_binary_path) != NULL) {
        if (!filehash_calculate(daemon_binary_path, daemon_sha256, sizeof(daemon_sha256))) {
            fprintf(stderr, "Warning: Could not hash daemon binary\n");
            strncpy(daemon_sha256, "unknown", sizeof(daemon_sha256));
            daemon_sha256[sizeof(daemon_sha256) - 1] = '\0';
        }
    } else {
        strncpy(daemon_binary_path, argv[0], sizeof(daemon_binary_path));
        daemon_binary_path[sizeof(daemon_binary_path) - 1] = '\0';
        strncpy(daemon_sha256, "unknown", sizeof(daemon_sha256));
        daemon_sha256[sizeof(daemon_sha256) - 1] = '\0';
    }

    // Calculate config file hash (for tamper detection)
    if (!filehash_calculate(config_path, config_sha256, sizeof(config_sha256))) {
        fprintf(stderr, "Warning: Could not hash config file\n");
        strncpy(config_sha256, "unknown", sizeof(config_sha256));
        config_sha256[sizeof(config_sha256) - 1] = '\0';
    }

    // Record daemon start time for uptime tracking
    daemon_start_time = time(NULL);

    // ═══════════════════════════════════════════════════════════════════════════
    // PRIVILEGE DROPPING SEQUENCE
    // ═══════════════════════════════════════════════════════════════════════════
    //
    // SECURITY-CRITICAL: This sequence drops from root (UID 0) to nobody (UID 65534)
    // while retaining ONLY CAP_SYS_PTRACE for security monitoring.
    //
    // CRITICAL ORDER - MUST be performed in this EXACT sequence:
    //
    //   1. Load BPF programs (requires CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN)
    //   2. Open log file (requires write access to /var/log/linmon/)
    //   3. Calculate daemon and config hashes (requires CAP_DAC_READ_SEARCH)
    //   4. Prepare capabilities - Set CAP_SYS_PTRACE as ambient
    //   5. Drop supplementary groups (prevents retaining dangerous memberships)
    //   6. Drop GID to 65534 (nobody group)
    //   7. Drop UID to 65534 (nobody user) - POINT OF NO RETURN
    //   8. Drop CAP_SETUID and CAP_SETGID from PERMITTED/EFFECTIVE
    //   9. Verify cannot regain root (security assertion)
    //
    // WHY THIS ORDER MATTERS:
    //
    //   Steps 1-3: MUST be done as root (require privileged operations)
    //     - BPF loading requires CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN + CAP_SYS_RESOURCE
    //     - Log file creation may need write to /var/log (root-owned directory)
    //     - Hash calculation may need to read executable (CAP_DAC_READ_SEARCH)
    //
    //   Step 4: MUST be done BEFORE UID change (requires root)
    //     - Setting securebits requires root privileges
    //     - Ambient capability setup requires CAP_SETPCAP (root has this)
    //     - After this step, capability survives UID change
    //
    //   Step 5: Supplementary groups MUST be dropped BEFORE UID/GID change
    //     - Prevents retaining dangerous group memberships like:
    //       * disk (raw disk access)
    //       * adm (read system logs)
    //       * docker (container escape)
    //       * sudo (privilege escalation)
    //     - setgroups() requires root or CAP_SETGID
    //     - After UID drop, we won't have this capability
    //
    //   Step 6: GID MUST be dropped BEFORE UID for security
    //     - POSIX requirement: setgid() may require privileges
    //     - After UID drop to nobody, setgid() would fail
    //     - This prevents UID/GID mismatch (security best practice)
    //
    //   Step 7: UID drop is the POINT OF NO RETURN
    //     - After setuid(65534), process can NEVER regain root
    //     - All privileged operations must be done BEFORE this
    //     - Ambient CAP_SYS_PTRACE survives (only capability retained)
    //
    //   Step 8: Drop CAP_SETUID and CAP_SETGID AFTER UID change
    //     - These capabilities allow changing UID/GID
    //     - Removing them prevents regaining root privileges
    //     - Must be done AFTER UID change (need CAP_SETUID for setuid())
    //     - Final capability set: ONLY CAP_SYS_PTRACE
    //
    //   Step 9: Verification - paranoid security check
    //     - Attempt setuid(0) - MUST fail
    //     - If it succeeds, something is wrong (abort)
    //     - Defense-in-depth: catch configuration errors early
    //
    // WHAT THE DAEMON CAN DO AFTER PRIVILEGE DROP:
    //   ✓ Read /proc/<pid>/exe for all users (CAP_SYS_PTRACE)
    //   ✓ Write to /var/log/linmon/events.json (file already open)
    //   ✓ Read from BPF ring buffers (BPF programs already loaded)
    //   ✓ Read configuration file /etc/linmon/linmon.conf (world-readable)
    //   ✓ Execute stat(), readlink(), open() on /proc (CAP_SYS_PTRACE)
    //
    // WHAT THE DAEMON CANNOT DO AFTER PRIVILEGE DROP:
    //   ✗ Load new BPF programs (CAP_BPF dropped)
    //   ✗ Modify system files (CAP_DAC_OVERRIDE dropped)
    //   ✗ Change file ownership (CAP_CHOWN, CAP_FOWNER dropped)
    //   ✗ Regain root privileges (CAP_SETUID, CAP_SETGID dropped)
    //   ✗ Access files outside /var/log/linmon and /proc
    //   ✗ Ptrace/modify other processes (read-only /proc access)
    //
    // WHY CAP_SYS_PTRACE IS RETAINED (security trade-off):
    //   - Required for reading /proc/<pid>/exe across UID boundaries
    //   - Essential for masquerading detection (T1036.004 - MITRE ATT&CK)
    //   - Daemon only uses for read-only /proc access (readlink, stat, open)
    //   - WARNING: Capability DOES permit ptrace(2) syscalls if code is compromised
    //   - Defense: Daemon runs as UID 65534 (nobody), minimal attack surface
    //   - No viable alternative (setuid wrapper would be worse security risk)
    //
    // DEFENSE IN DEPTH:
    //   - Daemon drops to lowest privilege possible (UID 65534)
    //   - Retains absolute minimum capability (only CAP_SYS_PTRACE)
    //   - Cannot regain root (CAP_SETUID explicitly dropped)
    //   - Log file already open (no need to create new files)
    //   - BPF programs already loaded (no need to reload)
    //   - Configuration reload reopens log file (safe operation)
    //
    // TESTING:
    //   After privilege drop, verify with:
    //     cat /proc/$(pidof linmond)/status | grep Cap
    //     # Should show CAP_SYS_PTRACE only (0x0000000000100000)
    //
    //   Verify cannot regain root:
    //     sudo -u linmond setuid 0  # Should fail
    //
    // ═══════════════════════════════════════════════════════════════════════════

    // STEP 4: Prepare capabilities BEFORE dropping UID/GID
    //
    // This MUST be done as root (requires CAP_SETPCAP and ability to set securebits)
    // Sets CAP_SYS_PTRACE as ambient so it survives the UID change to nobody
    if (getuid() == 0) {
        err = prepare_capabilities();
        if (err) {
            fprintf(stderr, "CRITICAL: Failed to prepare capabilities - aborting for security\n");
            fprintf(stderr, "  Cannot proceed without CAP_SYS_PTRACE for masquerading detection\n");
            goto cleanup;
        }
    }

    // STEP 5-7: Drop privileges from root to nobody
    //
    // This sequence drops UID 0 → 65534 (nobody) while:
    //   - Clearing all supplementary groups
    //   - Retaining ONLY CAP_SYS_PTRACE (via ambient capability)
    //   - Ensuring cannot regain root privileges
    if (getuid() == 0) {
        // STEP 5: Drop supplementary groups FIRST
        //
        // Supplementary groups are additional group memberships beyond primary GID
        // Examples of dangerous groups: disk, adm, docker, sudo, wheel
        //
        // Why drop these:
        //   - disk group: Raw disk access (/dev/sda → read encryption keys, tamper with filesystems)
        //   - adm group: Read system logs (/var/log → access sensitive data)
        //   - docker group: Container escape (docker socket → spawn root container)
        //   - sudo group: Privilege escalation (if misconfigured sudoers)
        //
        // setgroups(0, NULL) clears ALL supplementary groups
        // Must be done BEFORE UID change (requires CAP_SETGID)
        if (setgroups(0, NULL) != 0) {
            fprintf(stderr, "CRITICAL: Failed to drop supplementary groups: %s\n", strerror(errno));
            fprintf(stderr, "  Cannot continue - may retain dangerous group memberships\n");
            goto cleanup;
        }

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

        // STEP 8: Drop CAP_SETUID and CAP_SETGID from capability sets
        //
        // Why drop these:
        //   - CAP_SETUID allows changing UID (even back to root)
        //   - CAP_SETGID allows changing GID
        //   - These would allow regaining privileges (security violation)
        //
        // Why drop AFTER setuid():
        //   - We needed CAP_SETUID to call setuid(65534) above
        //   - Now that we're nobody, we don't need it anymore
        //
        // Final capability set after this:
        //   - AMBIENT: CAP_SYS_PTRACE
        //   - PERMITTED: CAP_SYS_PTRACE (CAP_SETUID/CAP_SETGID cleared)
        //   - EFFECTIVE: CAP_SYS_PTRACE (CAP_SETUID/CAP_SETGID cleared)
        //   - INHERITABLE: CAP_SYS_PTRACE
        //
        // Security property: Cannot regain root or change UID/GID ever again
        cap_t caps = cap_get_proc();
        if (caps) {
            cap_value_t drop_caps[2] = { CAP_SETUID, CAP_SETGID };

            // Clear from PERMITTED (removes from superset of allowed capabilities)
            cap_set_flag(caps, CAP_PERMITTED, 2, drop_caps, CAP_CLEAR);

            // Clear from EFFECTIVE (removes from active capabilities)
            cap_set_flag(caps, CAP_EFFECTIVE, 2, drop_caps, CAP_CLEAR);

            if (cap_set_proc(caps) != 0) {
                // This is a warning, not a critical error
                // Even if this fails, we can't regain root without CAP_SETUID
                fprintf(stderr, "Warning: Failed to drop SETUID/SETGID capabilities: %s\n",
                        strerror(errno));
            }
            cap_free(caps);
        }

        // STEP 9: Verify cannot regain root - PARANOID SECURITY CHECK
        //
        // This is defense-in-depth verification
        // Attempt to setuid(0) - this MUST fail
        //
        // If it succeeds, something is catastrophically wrong:
        //   - CAP_SETUID was not dropped properly
        //   - Kernel capability system is broken
        //   - Security configuration error
        //
        // Better to abort now than run with unexpected privileges
        if (setuid(0) == 0) {
            fprintf(stderr, "CRITICAL: Was able to regain root after dropping privileges!\n");
            fprintf(stderr, "  This indicates a severe security configuration error.\n");
            fprintf(stderr, "  Aborting to prevent potential security breach.\n");
            goto cleanup;
        }

        // SUCCESS: Privilege drop complete
        printf("✓ Dropped to UID/GID 65534 (nobody), cleared supplementary groups\n");
        printf("✓ Retained CAP_SYS_PTRACE for masquerading detection\n");
        printf("✓ Verified cannot regain root privileges\n");
    }

    // Set up ring buffer polling
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
                          NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("\nMonitoring active. Press Ctrl-C to exit, SIGHUP to reload config.\n");
    printf("Events logged to: %s\n",
           global_config.log_file ? global_config.log_file : "/var/log/linmon/events.json");

    // Log daemon startup (tamper detection - visible in syslog/journal)
    char startup_msg[64];
    snprintf(startup_msg, sizeof(startup_msg), "LinMon v%s monitoring started", LINMON_VERSION);
    log_daemon_event("daemon_start", startup_msg, 0, 0, 0,
                    LINMON_VERSION, daemon_sha256, config_sha256);

    // Periodic cache save tracking
    time_t last_cache_save = time(NULL);
    int cache_save_interval = global_config.cache_save_interval * 60;  // Convert to seconds

    // Periodic checkpoint tracking (tamper detection)
    time_t last_checkpoint = time(NULL);
    int checkpoint_interval = global_config.checkpoint_interval * 60;  // Convert to seconds

    // Periodic log file deletion check (T1070.001 detection)
    time_t last_logfile_check = time(NULL);
    const int logfile_check_interval = 10;  // Check every 10 seconds

    // Periodic authentication integrity check (T1556.003/004 detection)
    time_t last_auth_check = time(NULL);
    int auth_check_interval = global_config.auth_integrity_interval * 60;  // Convert to seconds

    // Main event loop - poll for events
    while (!exiting) {
        // Check for config reload
        if (reload_config) {
            // Recalculate config hash before reload (tamper detection)
            char new_config_sha256[SHA256_HEX_LEN];
            if (!filehash_calculate(config_path, new_config_sha256, sizeof(new_config_sha256))) {
                strncpy(new_config_sha256, "error", sizeof(new_config_sha256));
                new_config_sha256[sizeof(new_config_sha256) - 1] = '\0';
            }

            // Log config reload with sender info (tamper detection)
            log_daemon_event("daemon_reload", "Configuration reload requested",
                            SIGHUP, signal_sender_pid, signal_sender_uid,
                            LINMON_VERSION, daemon_sha256, new_config_sha256);
            printf("\n[SIGHUP] Reloading configuration...\n");

            struct linmon_config new_config = {0};
            err = load_config(&new_config, config_path);
            if (err && err != -ENOENT) {
                fprintf(stderr, "Failed to reload config: %s\n", strerror(-err));
                reload_config = false;
                continue;
            }

            // Initialize new logger BEFORE closing old one (avoid race condition)
            // Use secure file opening to prevent permission vulnerabilities
            const char *new_log_file = new_config.log_file ? new_config.log_file : "/var/log/linmon/events.json";
            FILE *new_log_fp = logger_open_file_secure(new_log_file);
            if (!new_log_fp) {
                fprintf(stderr, "CRITICAL: Failed to open new log file %s: %s\n",
                        new_log_file, strerror(errno));
                free_config(&new_config);
                reload_config = false;
                continue;
            }

            // Update global config
            free_config(&global_config);
            global_config = new_config;

            // Update BPF config map
            err = update_bpf_config(bpf_map__fd(skel->maps.config_map), &global_config);
            if (err) {
                fprintf(stderr, "Warning: Failed to update BPF config: %d\n", err);
            }

            // Update network CIDR filtering
            err = update_network_filters(bpf_map__fd(skel->maps.ignore_networks_map), &global_config);
            if (err) {
                fprintf(stderr, "Warning: Failed to update network filters: %d\n", err);
            }

            // Reinitialize filter
            filter_init(&global_config);

            // Atomically swap logger (close old, use new)
            // This ensures handle_event() never sees NULL log_fp
            logger_replace(new_log_fp);

            // Update logger enrichment options
            logger_set_enrichment(global_config.resolve_usernames,
                                 global_config.hash_binaries,
                                 global_config.verify_packages,
                                 global_config.capture_container_metadata);

            // Update syslog setting
            logger_set_syslog(global_config.log_to_syslog);

            printf("Configuration reloaded:\n");
            printf("  UID range: %u-%u\n", global_config.min_uid, global_config.max_uid);
            printf("  Require TTY: %s\n", global_config.require_tty ? "yes" : "no");
            printf("  Redact sensitive: %s\n", global_config.redact_sensitive ? "yes" : "no");
            printf("  Resolve usernames: %s\n", global_config.resolve_usernames ? "yes" : "no");
            printf("  Hash binaries: %s\n", global_config.hash_binaries ? "yes" : "no");
            printf("  Syslog output: %s\n", global_config.log_to_syslog ? "yes" : "no");
            printf("  Log file reopened (logrotate support)\n");

            // Save caches on reload (ensures data persistence)
            if (global_config.hash_binaries)
                filehash_save();
            if (global_config.verify_packages)
                pkgcache_save();

            // Update cache save interval
            cache_save_interval = global_config.cache_save_interval * 60;
            last_cache_save = time(NULL);

            // Update checkpoint interval
            checkpoint_interval = global_config.checkpoint_interval * 60;

            // Update auth integrity check interval
            auth_check_interval = global_config.auth_integrity_interval * 60;

            // Update stored config hash after successful reload
            strncpy(config_sha256, new_config_sha256, sizeof(config_sha256));
            config_sha256[sizeof(config_sha256) - 1] = '\0';

            reload_config = false;
        }

        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            // Interrupted, likely by signal
            err = 0;
            continue;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }

        // Periodic cache save (if configured)
        if (cache_save_interval > 0) {
            time_t now = time(NULL);
            if (now - last_cache_save >= cache_save_interval) {
                if (global_config.hash_binaries)
                    filehash_save();
                if (global_config.verify_packages)
                    pkgcache_save();
                last_cache_save = now;
            }
        }

        // Periodic checkpoint (tamper detection)
        if (checkpoint_interval > 0) {
            time_t now = time(NULL);
            if (now - last_checkpoint >= checkpoint_interval) {
                log_checkpoint_to_syslog();
                last_checkpoint = now;
            }
        }

        // Periodic log file deletion check (T1070.001 - Indicator Removal)
        {
            time_t now = time(NULL);
            if (now - last_logfile_check >= logfile_check_interval) {
                if (logger_check_file_deleted()) {
                    // Log file was deleted and recovered
                    // Critical alert already sent to syslog by logger_check_file_deleted()
                    fprintf(stderr, "WARNING: Log file was deleted - recovered with new file\n");
                }
                last_logfile_check = now;
            }
        }

        // Periodic authentication integrity check (T1556.003/004 - Modify Authentication)
        if (global_config.monitor_auth_integrity && auth_check_interval > 0) {
            time_t now = time(NULL);
            if (now - last_auth_check >= auth_check_interval) {
                int violations = authcheck_verify_all();
                if (violations > 0) {
                    // Violations detected and logged
                    // Critical alerts already sent to syslog by authcheck_verify_all()
                    fprintf(stderr, "WARNING: %d authentication file integrity violation(s) detected\n",
                            violations);
                }
                last_auth_check = now;
            }
        }
    }

    // Log shutdown with signal info (tamper detection - who stopped us?)
    if (last_signal > 0) {
        log_daemon_event("daemon_shutdown", "LinMon terminated by signal",
                        last_signal, signal_sender_pid, signal_sender_uid,
                        LINMON_VERSION, daemon_sha256, config_sha256);
    }

    // Print shutdown statistics
    printf("\nLinMon shutting down...\n");
    if (global_config.hash_binaries) {
        unsigned long hits, misses, entries, recomputes;
        filehash_stats(&hits, &misses, &entries, &recomputes);
        printf("  SHA256 cache: %lu hits, %lu misses, %lu entries, %lu recomputes\n",
               hits, misses, entries, recomputes);
    }
    if (global_config.verify_packages) {
        unsigned long hits, misses, entries, recomputes;
        pkgcache_stats(&hits, &misses, &entries, &recomputes);
        printf("  Package cache: %lu hits, %lu misses, %lu entries, %lu recomputes\n",
               hits, misses, entries, recomputes);
    }

cleanup:
    // Close syslog
    closelog();

    // Cleanup
    ring_buffer__free(rb);
    linmon_bpf__destroy(skel);
    logger_cleanup();
    userdb_cleanup();
    filehash_cleanup();
    pkgcache_cleanup();
    free_config(&global_config);

    return err < 0 ? -err : 0;
}
