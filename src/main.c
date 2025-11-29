// SPDX-License-Identifier: GPL-2.0
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
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "logger.h"
#include "config.h"
#include "filter.h"
#include "userdb.h"
#include "filehash.h"
#include "procfs.h"
#include "linmon.skel.h"
#include "../bpf/common.h"
#include <arpa/inet.h>

static volatile bool exiting = false;
static volatile bool reload_config = false;

static struct linmon_config global_config = {0};
static const char *config_path = "/etc/linmon/linmon.conf";

static void sig_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM) {
        exiting = true;
    } else if (sig == SIGHUP) {
        reload_config = true;
    }
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

static int drop_capabilities(void)
{
    cap_t caps;
    int ret;

    // Get current capabilities
    caps = cap_get_proc();
    if (!caps) {
        fprintf(stderr, "Failed to get capabilities: %s\n", strerror(errno));
        return -1;
    }

    // Clear all capabilities (drop everything)
    // After BPF programs are loaded and attached, we don't need any capabilities
    ret = cap_clear(caps);
    if (ret) {
        fprintf(stderr, "Failed to clear capabilities: %s\n", strerror(errno));
        cap_free(caps);
        return -1;
    }

    // Apply the cleared capability set
    ret = cap_set_proc(caps);
    if (ret) {
        fprintf(stderr, "Failed to set capabilities: %s\n", strerror(errno));
        cap_free(caps);
        return -1;
    }

    cap_free(caps);
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

    case EVENT_PRIV_SETUID:
    case EVENT_PRIV_SETGID:
    case EVENT_PRIV_SUDO: {
        if (data_sz < sizeof(struct privilege_event)) {
            fprintf(stderr, "Invalid privilege event size: %zu\n", data_sz);
            return 0;
        }
        struct privilege_event *e = data;

        // Always log privilege escalation events
        logger_log_privilege_event(e);
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
    prefix_len = atoi(slash + 1);

    if (prefix_len < 0 || prefix_len > 32) {
        fprintf(stderr, "Invalid CIDR prefix length: %d\n", prefix_len);
        return -1;
    }

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
    while (cidr_token && index < 32) {
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
            printf("LinMon version 1.0.0\n");
            printf("eBPF-based system monitoring for Linux\n");
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    // Set up signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP, sig_handler);

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

    // Initialize user database and file hashing
    userdb_init();
    filehash_init();

    // Configure logger enrichment options
    logger_set_enrichment(global_config.resolve_usernames,
                         global_config.hash_binaries);

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

    // Initialize filter
    filter_init(&global_config);

    // Load and open BPF application
    skel = linmon_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load LinMon BPF programs\n");
        err = -1;
        goto cleanup;
    }

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

    // Attach all BPF programs
    err = linmon_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach LinMon BPF programs: %d\n", err);
        goto cleanup;
    }

    printf("✓ All monitoring programs attached\n");
    printf("  - Process exec/exit monitoring\n");
    if (global_config.monitor_files)
        printf("  - File create/modify/delete monitoring (with rate limiting)\n");
    if (global_config.monitor_tcp)
        printf("  - TCP connect/accept monitoring\n");
    if (global_config.monitor_udp)
        printf("  - UDP send monitoring\n");
    printf("  - Privilege escalation monitoring (sudo/su/setuid/setgid)\n");

    // Drop UID/GID to nobody user if running as root
    // IMPORTANT: This must be done BEFORE dropping capabilities
    // (we need CAP_SETUID/CAP_SETGID to change UID/GID)
    if (getuid() == 0) {
        // Drop GID first (must be done before UID for security)
        if (setgid(65534) != 0) {
            fprintf(stderr, "CRITICAL: Failed to drop GID to nobody: %s\n", strerror(errno));
            goto cleanup;
        }
        if (setuid(65534) != 0) {
            fprintf(stderr, "CRITICAL: Failed to drop UID to nobody: %s\n", strerror(errno));
            goto cleanup;
        }

        // Verify we can't regain root
        if (setuid(0) == 0) {
            fprintf(stderr, "CRITICAL: Was able to regain root after dropping privileges!\n");
            goto cleanup;
        }

        printf("✓ Dropped to UID/GID 65534 (nobody)\n");
    }

    // Drop all capabilities now that BPF programs are loaded and attached
    // This reduces attack surface - we no longer need root privileges
    // IMPORTANT: This must be done AFTER dropping UID/GID
    err = drop_capabilities();
    if (err) {
        fprintf(stderr, "CRITICAL: Failed to drop capabilities - aborting for security\n");
        goto cleanup;
    }
    printf("✓ Dropped all capabilities (running with minimal privileges)\n");

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

    // Main event loop - poll for events
    while (!exiting) {
        // Check for config reload
        if (reload_config) {
            printf("\n[SIGHUP] Reloading configuration...\n");

            struct linmon_config new_config = {0};
            err = load_config(&new_config, config_path);
            if (err && err != -ENOENT) {
                fprintf(stderr, "Failed to reload config: %s\n", strerror(-err));
            } else {
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

                // Reopen log file (for logrotate support)
                // Close old logger and reopen with new/same file
                logger_cleanup();
                err = logger_init(global_config.log_file ? global_config.log_file :
                                 "/var/log/linmon/events.json");
                if (err) {
                    fprintf(stderr, "CRITICAL: Failed to reopen log file: %s\n", strerror(-err));
                    exiting = true;
                    goto reload_done;
                }

                // Update logger enrichment options
                logger_set_enrichment(global_config.resolve_usernames,
                                     global_config.hash_binaries);

                printf("Configuration reloaded:\n");
                printf("  UID range: %u-%u\n", global_config.min_uid, global_config.max_uid);
                printf("  Require TTY: %s\n", global_config.require_tty ? "yes" : "no");
                printf("  Redact sensitive: %s\n", global_config.redact_sensitive ? "yes" : "no");
                printf("  Resolve usernames: %s\n", global_config.resolve_usernames ? "yes" : "no");
                printf("  Hash binaries: %s\n", global_config.hash_binaries ? "yes" : "no");
                printf("  Log file reopened (logrotate support)\n");
            }

reload_done:
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
    }

    printf("\nLinMon shutting down...\n");

cleanup:
    // Cleanup
    ring_buffer__free(rb);
    linmon_bpf__destroy(skel);
    logger_cleanup();
    userdb_cleanup();
    filehash_cleanup();
    free_config(&global_config);

    return err < 0 ? -err : 0;
}
