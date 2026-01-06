// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// Configuration management

#ifndef __LINMON_CONFIG_H
#define __LINMON_CONFIG_H

#include <stdbool.h>

struct linmon_config {
    char *log_file;
    bool log_to_syslog;

    // Built-in log rotation (can be disabled for external logrotate)
    bool log_rotate;              // Enable built-in rotation (default: true)
    unsigned long log_rotate_size; // Max size in bytes before rotation (default: 100MB)
    int log_rotate_count;         // Number of rotated files to keep (default: 10)

    bool monitor_processes;
    bool monitor_process_exit;  // Monitor process exit events
    bool monitor_files;
    bool monitor_tcp;
    bool monitor_udp;
    bool monitor_vsock;         // Monitor vsock (VM/container communication)
    int verbosity;

    // UID/GID filtering
    unsigned int min_uid;
    unsigned int max_uid;

    // Session filtering
    bool require_tty;         // Only log processes with controlling TTY
    bool ignore_threads;      // Only log main processes (pid == tgid), not threads

    // Command-line capture and redaction
    bool capture_cmdline;
    bool redact_sensitive;

    // Enrichment options
    bool resolve_usernames;   // Resolve UID to username
    bool hash_binaries;       // Calculate SHA256 of executables
    bool verify_packages;     // Check if binaries belong to system packages

    // Cache settings
    char *hash_cache_file;    // Path to hash cache file (default: /var/cache/linmon/hashes.cache)
    int hash_cache_size;      // Max entries in hash cache (default: 10000)
    char *pkg_cache_file;     // Path to package cache file (default: /var/cache/linmon/packages.cache)
    int pkg_cache_size;       // Max entries in package cache (default: 10000)
    int cache_save_interval;  // Minutes between periodic cache saves (default: 5, 0=shutdown only)

    // Tamper detection
    int checkpoint_interval;  // Minutes between integrity checkpoints (default: 30, 0=disabled)

    // Process filtering
    char *ignore_processes;   // Comma-separated blacklist
    char *only_processes;     // Comma-separated whitelist

    // Network filtering
    char *ignore_networks;    // Comma-separated CIDR blocks to ignore

    // File path filtering
    char *ignore_file_paths;  // Comma-separated file path prefixes to ignore

    // Security monitoring (MITRE ATT&CK detection)
    bool monitor_ptrace;      // T1055 - Process injection via ptrace
    bool monitor_modules;     // T1547.006 - Kernel module loading
    bool monitor_memfd;       // T1620 - Fileless malware via memfd_create
    bool monitor_bind;        // T1571 - Bind shells / C2 servers
    bool monitor_unshare;     // T1611 - Container escape / namespace manipulation
    bool monitor_execveat;    // T1620 - Fileless execution (fd-based)
    bool monitor_bpf;         // T1014 - eBPF rootkit / packet manipulation
    bool monitor_cred_read;   // T1003.008 - Credential file read (/etc/shadow)
    bool monitor_ldpreload;   // T1574.006 - LD_PRELOAD hijacking
    bool monitor_persistence; // T1053, T1547 - Persistence mechanisms (cron, systemd, shell profiles)
    bool monitor_suid;        // T1548.001 - SUID/SGID manipulation (chmod +s)
    bool monitor_cred_write;  // T1098.001 - Account manipulation (credential file writes)
    bool monitor_log_tamper;  // T1070.001 - Log tampering (deletion/truncation)
};

// Load configuration from file
int load_config(struct linmon_config *config, const char *config_file);

// Free configuration resources
void free_config(struct linmon_config *config);

#endif /* __LINMON_CONFIG_H */
