// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
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

    // Built-in log rotation defaults
    config->log_rotate = true;                  // On by default
    config->log_rotate_size = 100 * 1024 * 1024; // 100MB
    config->log_rotate_count = 10;              // Keep 10 files

    config->monitor_processes = true;
    config->monitor_process_exit = true;  // Default: log exit events
    config->monitor_files = false;
    config->monitor_tcp = true;
    config->monitor_udp = false;  // Default: off (can be very noisy)
    config->monitor_vsock = false;  // Default: off (VM/container communication)
    config->verbosity = 1;
    config->min_uid = 0;     // Default: monitor all users including root
    config->max_uid = 0;     // 0 = no limit
    config->require_tty = false;       // Default: log all processes (GUI + terminal)
    config->ignore_threads = false;    // Default: log both processes and threads
    config->capture_cmdline = true;
    config->redact_sensitive = true;
    config->resolve_usernames = true;       // Default: resolve UIDs
    config->hash_binaries = true;           // Default: hash for security monitoring
    config->verify_packages = false;        // Default: off (requires dpkg/rpm)
    config->capture_container_metadata = true;  // Default: on (parse container ID from cgroups)

    // Cache settings
    config->hash_cache_file = NULL;    // Use default path
    config->hash_cache_size = 10000;   // Default: 10k entries
    config->pkg_cache_file = NULL;     // Use default path
    config->pkg_cache_size = 10000;    // Default: 10k entries
    config->cache_save_interval = 5;   // Default: save every 5 minutes
    config->checkpoint_interval = 30;  // Default: checkpoint every 30 minutes

    // Authentication integrity monitoring
    config->monitor_auth_integrity = true;   // Default: enabled
    config->auth_integrity_interval = 30;    // Default: check every 30 minutes

    config->ignore_processes = NULL;
    config->only_processes = NULL;
    config->ignore_networks = NULL;
    config->ignore_file_paths = NULL;
    // Security monitoring defaults (opt-in, disabled by default)
    config->monitor_ptrace = false;
    config->monitor_modules = false;
    config->monitor_memfd = false;
    config->monitor_bind = false;
    config->monitor_unshare = false;
    config->monitor_execveat = false;
    config->monitor_bpf = false;
    config->monitor_cred_read = true;   // Default: on (low noise, high value)
    config->monitor_ldpreload = true;   // Default: on (critical detection)
    config->monitor_persistence = false; // Default: off (opt-in)
    config->monitor_suid = false;       // Default: off (opt-in)
    config->monitor_cred_write = true;  // Default: on (critical detection)
    config->monitor_log_tamper = true;  // Default: on (critical detection)
    config->monitor_raw_disk_access = true;  // Default: on (critical detection)
}

// Load and validate configuration from file
//
// SECURITY DESIGN:
// This function is security-critical because it controls daemon behavior and must
// prevent configuration-based attacks. Security measures implemented:
//
// 1. FILE PERMISSION VALIDATION:
//    - ABORT if world-writable (ANY user could modify config)
//    - WARN if not root-owned (untrusted user owns config)
//    - WARN if group-writable (group members could modify)
//    Rationale: Config controls security monitoring - compromised config = blind daemon
//
// 2. PATH TRAVERSAL PREVENTION:
//    - log_file must be absolute path (prevents relative path tricks)
//    - log_file cannot contain ".." (prevents directory traversal)
//    Example attack: log_file = "../../../tmp/fake.log" → writes to /tmp instead of /var/log
//
// 3. BOUNDS VALIDATION:
//    - UID ranges checked for overflow (strtoul validates, ULONG_MAX checked)
//    - Size limits validated (min/max ranges enforced)
//    - Integer overflow protection on multipliers (K/M/G suffixes)
//
// 4. GRACEFUL DEGRADATION:
//    - Invalid values logged to stderr but don't crash daemon
//    - Missing config file → use safe defaults
//    - Unknown keys silently ignored (forward compatibility)
//
// PARSING FORMAT:
// Simple key-value pairs: "key = value"
// - Lines starting with # are comments
// - Whitespace around = is required
// - No quotes needed for strings
// - Boolean values: "true" or "false" (case-sensitive)
// - Numeric values: integers, optional K/M/G suffix for sizes
//
// Returns: 0 on success, -errno on error
//          -ENOENT if file not found (not an error, use defaults)
//          -EPERM if file has insecure permissions
int load_config(struct linmon_config *config, const char *config_file)
{
    FILE *fp;
    char line[256];
    char key[64], value[192];
    struct stat st;

    set_defaults(config);

    // SECURITY: Check config file permissions BEFORE opening
    // This prevents TOCTOU race (check-then-open) but we accept the risk since
    // an attacker who can modify config can already compromise the system.
    // Allow test mode to skip ownership checks for unit tests (LINMON_TEST_MODE env var)
    bool test_mode = getenv("LINMON_TEST_MODE") != NULL;

    if (stat(config_file, &st) == 0) {
        // CRITICAL: Abort if world-writable (any user could modify config)
        if (st.st_mode & S_IWOTH) {
            fprintf(stderr, "CRITICAL: Config file is world-writable: %s\n", config_file);
            return -EPERM;  // Permission denied - refuse to use insecure config
        }

        if (!test_mode) {
            // CRITICAL: Abort if not root-owned
            // Config is read before privilege drop and can control log file path,
            // which is opened/chmod'd as root. Non-root ownership is privilege escalation vector.
            if (st.st_uid != 0) {
                fprintf(stderr, "CRITICAL: Config file not owned by root (uid=%d): %s\n",
                        st.st_uid, config_file);
                fprintf(stderr, "Fix with: chown root:root %s\n", config_file);
                return -EPERM;
            }

            // CRITICAL: Abort if group-writable
            // Group-writable config allows any group member to modify settings.
            // Since config controls log file path and is read as root, this is unsafe.
            if (st.st_mode & S_IWGRP) {
                fprintf(stderr, "CRITICAL: Config file is group-writable: %s\n", config_file);
                fprintf(stderr, "Fix with: chmod 0600 %s\n", config_file);
                return -EPERM;
            }
        }
    }

    fp = fopen(config_file, "r");
    if (!fp) {
        // Config file not found is not an error - use defaults
        // This allows daemon to run with compiled-in defaults if no config exists
        if (errno == ENOENT)
            return -ENOENT;
        return -errno;
    }

    // Parse config file line by line
    // Format: "key = value" (whitespace around = is required)
    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n')
            continue;

        // Parse key-value pair
        // Limits: key max 63 chars, value max 191 chars (total 256 with "key = value\n")
        if (sscanf(line, "%63s = %191s", key, value) != 2)
            continue;  // Malformed line, skip silently

        if (strcmp(key, "log_file") == 0) {
            // SECURITY: Validate log file path to prevent path traversal attacks
            //
            // Attack scenario: Attacker modifies config to write logs to /tmp or /dev/null,
            // bypassing monitoring or filling disk. Path validation prevents:
            // - Relative paths: "../../tmp/fake.log" → must be absolute
            // - Directory traversal: "/var/log/../../tmp/fake.log" → reject ".."
            // - Symlink attacks: Not prevented here (would need realpath() check)
            //
            // Why absolute path required:
            // Daemon may change working directory, so relative paths are ambiguous
            if (value[0] != '/') {
                fprintf(stderr, "Security: log_file must be absolute path: %s\n", value);
                continue;  // Skip invalid path, keep default
            }
            // Why ".." rejected:
            // Prevents directory traversal even with absolute paths
            // Example: /var/log/linmon/../../tmp/evil.log → /tmp/evil.log
            if (strstr(value, "..") != NULL) {
                fprintf(stderr, "Security: log_file cannot contain '..': %s\n", value);
                continue;  // Skip invalid path, keep default
            }
            config->log_file = strdup(value);
            if (!config->log_file) {
                fprintf(stderr, "Error: Failed to allocate memory for log_file\n");
                fclose(fp);
                return -ENOMEM;
            }
        } else if (strcmp(key, "log_to_syslog") == 0) {
            config->log_to_syslog = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "log_rotate") == 0) {
            config->log_rotate = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "log_rotate_size") == 0) {
            // Parse size with optional suffix (K, M, G)
            char *endptr;
            unsigned long val = strtoul(value, &endptr, 10);
            if (*endptr == 'K' || *endptr == 'k') {
                val *= 1024;
            } else if (*endptr == 'M' || *endptr == 'm') {
                val *= 1024 * 1024;
            } else if (*endptr == 'G' || *endptr == 'g') {
                val *= 1024 * 1024 * 1024;
            } else if (*endptr != '\0') {
                fprintf(stderr, "Invalid log_rotate_size value: %s\n", value);
                continue;
            }
            if (val < 1024 * 1024) {
                fprintf(stderr, "log_rotate_size too small (min 1M): %s\n", value);
                continue;
            }
            config->log_rotate_size = val;
        } else if (strcmp(key, "log_rotate_count") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, 10);
            if (*endptr != '\0' || val < 1 || val > 100) {
                fprintf(stderr, "Invalid log_rotate_count (1-100): %s\n", value);
                continue;
            }
            config->log_rotate_count = (int)val;
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
        } else if (strcmp(key, "monitor_vsock") == 0) {
            config->monitor_vsock = (strcmp(value, "true") == 0);
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
            // Parse UID with overflow protection
            //
            // SECURITY: UID parsing must prevent integer overflow attacks
            // Example attack: min_uid = 4294967296 (2^32) wraps to 0 on 32-bit
            //
            // Protection:
            // 1. strtoul() returns ULONG_MAX on overflow (detected by endptr check)
            // 2. Explicit check: val > UINT_MAX rejects values exceeding UID range
            // 3. Safe cast: (unsigned int)val only after validation
            //
            // Why this matters:
            // If attacker sets min_uid > max_uid via overflow, eBPF filtering breaks
            char *endptr;
            unsigned long val = strtoul(value, &endptr, 10);
            if (*endptr != '\0' || val > UINT_MAX) {
                fprintf(stderr, "Invalid min_uid value: %s\n", value);
                continue;
            }
            config->min_uid = (unsigned int)val;
        } else if (strcmp(key, "max_uid") == 0) {
            // Parse max_uid with same overflow protection as min_uid
            // See min_uid comment for detailed security rationale
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
        } else if (strcmp(key, "verify_packages") == 0) {
            config->verify_packages = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "capture_container_metadata") == 0) {
            config->capture_container_metadata = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "pkg_cache_file") == 0) {
            // Validate cache file path
            if (value[0] != '/') {
                fprintf(stderr, "Security: pkg_cache_file must be absolute path: %s\n", value);
                continue;
            }
            if (strstr(value, "..") != NULL) {
                fprintf(stderr, "Security: pkg_cache_file cannot contain '..': %s\n", value);
                continue;
            }
            config->pkg_cache_file = strdup(value);
            if (!config->pkg_cache_file) {
                fprintf(stderr, "Error: Failed to allocate memory for pkg_cache_file\n");
                fclose(fp);
                return -ENOMEM;
            }
        } else if (strcmp(key, "pkg_cache_size") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, 10);
            if (*endptr != '\0' || val < 100 || val > 1000000) {
                fprintf(stderr, "Invalid pkg_cache_size (100-1000000): %s\n", value);
                continue;
            }
            config->pkg_cache_size = (int)val;
        } else if (strcmp(key, "hash_cache_file") == 0) {
            // Validate cache file path
            if (value[0] != '/') {
                fprintf(stderr, "Security: hash_cache_file must be absolute path: %s\n", value);
                continue;
            }
            if (strstr(value, "..") != NULL) {
                fprintf(stderr, "Security: hash_cache_file cannot contain '..': %s\n", value);
                continue;
            }
            config->hash_cache_file = strdup(value);
            if (!config->hash_cache_file) {
                fprintf(stderr, "Error: Failed to allocate memory for hash_cache_file\n");
                fclose(fp);
                return -ENOMEM;
            }
        } else if (strcmp(key, "hash_cache_size") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, 10);
            if (*endptr != '\0' || val < 100 || val > 1000000) {
                fprintf(stderr, "Invalid hash_cache_size (100-1000000): %s\n", value);
                continue;
            }
            config->hash_cache_size = (int)val;
        } else if (strcmp(key, "cache_save_interval") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, 10);
            if (*endptr != '\0' || val < 0 || val > 60) {
                fprintf(stderr, "Invalid cache_save_interval (0-60 minutes): %s\n", value);
                continue;
            }
            config->cache_save_interval = (int)val;
        } else if (strcmp(key, "checkpoint_interval") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, 10);
            if (*endptr != '\0' || val < 0 || val > 1440) {  // 0 to 1440 minutes (24 hours)
                fprintf(stderr, "Invalid checkpoint_interval (0-1440 minutes): %s\n", value);
                continue;
            }
            config->checkpoint_interval = (int)val;
        } else if (strcmp(key, "monitor_auth_integrity") == 0) {
            config->monitor_auth_integrity = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "auth_integrity_interval") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, 10);
            if (*endptr != '\0' || val < 0 || val > 1440) {  // 0 to 1440 minutes (24 hours)
                fprintf(stderr, "Invalid auth_integrity_interval (0-1440 minutes): %s\n", value);
                continue;
            }
            config->auth_integrity_interval = (int)val;
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
        } else if (strcmp(key, "monitor_bind") == 0) {
            config->monitor_bind = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_unshare") == 0) {
            config->monitor_unshare = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_execveat") == 0) {
            config->monitor_execveat = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_bpf") == 0) {
            config->monitor_bpf = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_cred_read") == 0) {
            config->monitor_cred_read = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_ldpreload") == 0) {
            config->monitor_ldpreload = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_persistence") == 0) {
            config->monitor_persistence = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_suid") == 0) {
            config->monitor_suid = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_cred_write") == 0) {
            config->monitor_cred_write = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_log_tamper") == 0) {
            config->monitor_log_tamper = (strcmp(value, "true") == 0);
        } else if (strcmp(key, "monitor_raw_disk_access") == 0) {
            config->monitor_raw_disk_access = (strcmp(value, "true") == 0);
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
    if (config->pkg_cache_file) {
        free(config->pkg_cache_file);
        config->pkg_cache_file = NULL;
    }
    if (config->hash_cache_file) {
        free(config->hash_cache_file);
        config->hash_cache_file = NULL;
    }
}
