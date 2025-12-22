// SPDX-License-Identifier: GPL-2.0
// Configuration management implementation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <limits.h>

#include "config.h"

// Default configuration
static void set_defaults(struct linmon_config *config)
{
    config->log_file = NULL;
    config->log_to_syslog = false;
    config->monitor_processes = true;
    config->monitor_process_exit = true;  // Default: log exit events
    config->monitor_files = false;
    config->monitor_tcp = true;
    config->monitor_udp = false;  // Default: off (can be very noisy)
    config->verbosity = 1;
    config->min_uid = 1000;  // Default: ignore system users
    config->max_uid = 0;     // 0 = no limit
    config->require_tty = false;       // Default: log all processes (GUI + terminal)
    config->ignore_threads = false;    // Default: log both processes and threads
    config->capture_cmdline = true;
    config->redact_sensitive = true;
    config->resolve_usernames = true;  // Default: resolve UIDs
    config->hash_binaries = false;     // Default: don't hash (performance)
    config->ignore_processes = NULL;
    config->only_processes = NULL;
    config->ignore_networks = NULL;
    config->ignore_file_paths = NULL;
    // Security monitoring defaults (opt-in, disabled by default)
    config->monitor_ptrace = false;
    config->monitor_modules = false;
    config->monitor_memfd = false;
}

int load_config(struct linmon_config *config, const char *config_file)
{
    FILE *fp;
    char line[256];
    char key[64], value[192];
    struct stat st;

    set_defaults(config);

    // Check config file permissions before opening
    if (stat(config_file, &st) == 0) {
        // Warn if world-writable (critical security issue)
        if (st.st_mode & S_IWOTH) {
            fprintf(stderr, "CRITICAL: Config file is world-writable: %s\n", config_file);
            return -EPERM;
        }
        // Warn if not owned by root
        if (st.st_uid != 0) {
            fprintf(stderr, "Warning: Config file not owned by root (uid=%d): %s\n",
                    st.st_uid, config_file);
        }
        // Warn if group-writable
        if (st.st_mode & S_IWGRP) {
            fprintf(stderr, "Warning: Config file is group-writable: %s\n", config_file);
        }
    }

    fp = fopen(config_file, "r");
    if (!fp) {
        // Config file not found is not an error - use defaults
        if (errno == ENOENT)
            return -ENOENT;
        return -errno;
    }

    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n')
            continue;

        if (sscanf(line, "%63s = %191s", key, value) != 2)
            continue;

        if (strcmp(key, "log_file") == 0) {
            // Validate log file path for security
            if (value[0] != '/') {
                fprintf(stderr, "Security: log_file must be absolute path: %s\n", value);
                continue;
            }
            if (strstr(value, "..") != NULL) {
                fprintf(stderr, "Security: log_file cannot contain '..': %s\n", value);
                continue;
            }
            config->log_file = strdup(value);
            if (!config->log_file) {
                fprintf(stderr, "Error: Failed to allocate memory for log_file\n");
                fclose(fp);
                return -ENOMEM;
            }
        } else if (strcmp(key, "log_to_syslog") == 0) {
            config->log_to_syslog = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_processes") == 0) {
            config->monitor_processes = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_process_exit") == 0) {
            config->monitor_process_exit = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_files") == 0) {
            config->monitor_files = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_tcp") == 0) {
            config->monitor_tcp = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_udp") == 0) {
            config->monitor_udp = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_network") == 0) {
            // Legacy support: monitor_network sets both TCP and UDP
            bool val = (strcmp(value, "true") == 0);
            config->monitor_tcp = val;
            config->monitor_udp = val;
        } else if (strcmp(key, "verbosity") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, 10);
            if (*endptr != '\0' || val < 0 || val > 2) {
                fprintf(stderr, "Invalid verbosity value: %s (must be 0-2)\n", value);
                continue;
            }
            config->verbosity = (int)val;
        } else if (strcmp(key, "min_uid") == 0) {
            char *endptr;
            unsigned long val = strtoul(value, &endptr, 10);
            if (*endptr != '\0' || val > UINT_MAX) {
                fprintf(stderr, "Invalid min_uid value: %s\n", value);
                continue;
            }
            config->min_uid = (unsigned int)val;
        } else if (strcmp(key, "max_uid") == 0) {
            char *endptr;
            unsigned long val = strtoul(value, &endptr, 10);
            if (*endptr != '\0' || val > UINT_MAX) {
                fprintf(stderr, "Invalid max_uid value: %s\n", value);
                continue;
            }
            config->max_uid = (unsigned int)val;
        } else if (strcmp(key, "require_tty") == 0) {
            config->require_tty = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "ignore_threads") == 0) {
            config->ignore_threads = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "capture_cmdline") == 0) {
            config->capture_cmdline = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "redact_sensitive") == 0) {
            config->redact_sensitive = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "resolve_usernames") == 0) {
            config->resolve_usernames = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "hash_binaries") == 0) {
            config->hash_binaries = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "ignore_processes") == 0) {
            if (strlen(value) > 0) {
                config->ignore_processes = strdup(value);
                if (!config->ignore_processes) {
                    fprintf(stderr, "Error: Failed to allocate memory for ignore_processes\n");
                    fclose(fp);
                    return -ENOMEM;
                }
            }
        } else if (strcmp(key, "only_processes") == 0) {
            if (strlen(value) > 0) {
                config->only_processes = strdup(value);
                if (!config->only_processes) {
                    fprintf(stderr, "Error: Failed to allocate memory for only_processes\n");
                    fclose(fp);
                    return -ENOMEM;
                }
            }
        } else if (strcmp(key, "ignore_networks") == 0) {
            if (strlen(value) > 0) {
                config->ignore_networks = strdup(value);
                if (!config->ignore_networks) {
                    fprintf(stderr, "Error: Failed to allocate memory for ignore_networks\n");
                    fclose(fp);
                    return -ENOMEM;
                }
            }
        } else if (strcmp(key, "ignore_file_paths") == 0) {
            if (strlen(value) > 0) {
                config->ignore_file_paths = strdup(value);
                if (!config->ignore_file_paths) {
                    fprintf(stderr, "Error: Failed to allocate memory for ignore_file_paths\n");
                    fclose(fp);
                    return -ENOMEM;
                }
            }
        // Security monitoring (MITRE ATT&CK detection)
        } else if (strcmp(key, "monitor_ptrace") == 0) {
            config->monitor_ptrace = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_modules") == 0) {
            config->monitor_modules = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_memfd") == 0) {
            config->monitor_memfd = (strcmp(value, "true") == 0);
        }
    }

    fclose(fp);
    return 0;
}

void free_config(struct linmon_config *config)
{
    if (config->log_file) {
        free(config->log_file);
        config->log_file = NULL;
    }
    if (config->ignore_processes) {
        free(config->ignore_processes);
        config->ignore_processes = NULL;
    }
    if (config->only_processes) {
        free(config->only_processes);
        config->only_processes = NULL;
    }
    if (config->ignore_networks) {
        free(config->ignore_networks);
        config->ignore_networks = NULL;
    }
    if (config->ignore_file_paths) {
        free(config->ignore_file_paths);
        config->ignore_file_paths = NULL;
    }
}
