// SPDX-License-Identifier: GPL-2.0
// Configuration management

#ifndef __LINMON_CONFIG_H
#define __LINMON_CONFIG_H

#include <stdbool.h>

struct linmon_config {
    char *log_file;
    bool log_to_syslog;
    bool monitor_processes;
    bool monitor_process_exit;  // Monitor process exit events
    bool monitor_files;
    bool monitor_tcp;
    bool monitor_udp;
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
};

// Load configuration from file
int load_config(struct linmon_config *config, const char *config_file);

// Free configuration resources
void free_config(struct linmon_config *config);

#endif /* __LINMON_CONFIG_H */
