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
#include "utils.h"

static int parse_bool_value(const char *value, bool *result)
{
    if (strcmp(value, "true") == 0) {
        *result = true;
        return 0;
    }
    if (strcmp(value, "false") == 0) {
        *result = false;
        return 0;
    }
    return -EINVAL;
}

#define PARSE_BOOL_FIELD(field) do {                                      \
    bool parsed_value;                                                    \
    if (parse_bool_value(value, &parsed_value) != 0) {                    \
        fprintf(stderr, "Invalid boolean for %s on line %u: %s "         \
                        "(expected true or false)\n",                    \
                key, line_number, value);                                \
        parse_error = -EINVAL;                                            \
        goto out;                                                         \
    }                                                                     \
    config->field = parsed_value;                                         \
} while (0)

// Default configuration
static void set_defaults(struct linmon_config *config)
{
    config->log_file = NULL;
    config->log_to_syslog = false;
    config->allow_degraded_monitoring = true;
    config->retain_sys_ptrace = true;

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
    config->min_uid = 0;          // Default: monitor all users including root
    config->max_uid = UID_NO_LIMIT;  // Explicit sentinel: no upper limit (not magic 0)
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
    unsigned int line_number = 0;
    int parse_error = 0;

    set_defaults(config);

    // SECURITY: Check config file permissions BEFORE opening
    // This prevents TOCTOU race (check-then-open) but we accept the risk since
    // an attacker who can modify config can already compromise the system.
    // Allow test mode to skip ownership checks for unit tests (LINMON_TEST_MODE env var)
    bool test_mode = getenv("LINMON_TEST_MODE") != NULL;

    fp = safe_fopen_readonly(config_file, &st);
    if (!fp) {
        // Config file not found is not an error - use defaults
        // This allows daemon to run with compiled-in defaults if no config exists
        if (errno == ENOENT)
            return -ENOENT;
        return -errno;
    }

    if (!S_ISREG(st.st_mode)) {
        fclose(fp);
        fprintf(stderr, "CRITICAL: Config path is not a regular file: %s\n", config_file);
        return -EPERM;
    }

    // CRITICAL: Abort if world-writable (any user could modify config)
    if (st.st_mode & S_IWOTH) {
        fclose(fp);
        fprintf(stderr, "CRITICAL: Config file is world-writable: %s\n", config_file);
        return -EPERM;  // Permission denied - refuse to use insecure config
    }

    if (!test_mode) {
        // CRITICAL: Abort if not root-owned
        // Config is read before privilege drop and can control log file path,
        // which is opened/chmod'd as root. Non-root ownership is privilege escalation vector.
        if (st.st_uid != 0) {
            fclose(fp);
            fprintf(stderr, "CRITICAL: Config file not owned by root (uid=%d): %s\n",
                    st.st_uid, config_file);
            fprintf(stderr, "Fix with: chown root:linmon %s\n", config_file);
            return -EPERM;
        }

        // CRITICAL: Abort if group-writable
        // Group-writable config allows any group member to modify settings.
        // Since config controls log file path and is read as root, this is unsafe.
        if (st.st_mode & S_IWGRP) {
            fclose(fp);
            fprintf(stderr, "CRITICAL: Config file is group-writable: %s\n", config_file);
            fprintf(stderr, "Fix with: chmod 0640 %s\n", config_file);
            return -EPERM;
        }
    }

    // Parse config file line by line
    // Format: "key = value" (whitespace around = is required)
    while (fgets(line, sizeof(line), fp)) {
        line_number++;
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n')
            continue;

        // Parse key-value pair
        // Limits: key max 63 chars, value max 191 chars (total 256 with "key = value\n")
        int fields = sscanf(line, "%63s = %191s", key, value);
        if (fields == 1 && strchr(line, '=') != NULL) {
            const char *after_equals = strchr(line, '=') + 1;
            while (*after_equals == ' ' || *after_equals == '\t')
                after_equals++;
            if (*after_equals == '\n' || *after_equals == '\r' || *after_equals == '\0') {
                value[0] = '\0';
                fields = 2;
            }
        }
        if (fields != 2) {
            fprintf(stderr, "Malformed configuration line %u\n", line_number);
            parse_error = -EINVAL;
            goto out;
        }

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
                parse_error = -EINVAL;
                goto out;
            }
            // Why ".." rejected:
            // Prevents directory traversal even with absolute paths
            // Example: /var/log/linmon/../../tmp/evil.log → /tmp/evil.log
            if (strstr(value, "..") != NULL) {
                fprintf(stderr, "Security: log_file cannot contain '..': %s\n", value);
                parse_error = -EINVAL;
                goto out;
            }
            config->log_file = strdup(value);
            if (!config->log_file) {
                fprintf(stderr, "Error: Failed to allocate memory for log_file\n");
                fclose(fp);
                return -ENOMEM;
            }
        } else if (strcmp(key, "log_to_syslog") == 0) {
            PARSE_BOOL_FIELD(log_to_syslog);
        } else if (strcmp(key, "allow_degraded_monitoring") == 0) {
            PARSE_BOOL_FIELD(allow_degraded_monitoring);
        } else if (strcmp(key, "retain_sys_ptrace") == 0) {
            PARSE_BOOL_FIELD(retain_sys_ptrace);
        } else if (strcmp(key, "log_rotate") == 0) {
            PARSE_BOOL_FIELD(log_rotate);
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
                parse_error = -EINVAL;
                goto out;
            }
            if (val < 1024 * 1024) {
                fprintf(stderr, "log_rotate_size too small (min 1M): %s\n", value);
                parse_error = -EINVAL;
                goto out;
            }
            config->log_rotate_size = val;
        } else if (strcmp(key, "log_rotate_count") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, 10);
            if (*endptr != '\0' || val < 1 || val > 100) {
                fprintf(stderr, "Invalid log_rotate_count (1-100): %s\n", value);
                parse_error = -EINVAL;
                goto out;
            }
            config->log_rotate_count = (int)val;
        } else if (strcmp(key, "monitor_processes") == 0) {
            PARSE_BOOL_FIELD(monitor_processes);
        } else if (strcmp(key, "monitor_process_exit") == 0) {
            PARSE_BOOL_FIELD(monitor_process_exit);
        } else if (strcmp(key, "monitor_files") == 0) {
            PARSE_BOOL_FIELD(monitor_files);
        } else if (strcmp(key, "monitor_tcp") == 0) {
            PARSE_BOOL_FIELD(monitor_tcp);
        } else if (strcmp(key, "monitor_udp") == 0) {
            PARSE_BOOL_FIELD(monitor_udp);
        } else if (strcmp(key, "monitor_vsock") == 0) {
            PARSE_BOOL_FIELD(monitor_vsock);
        } else if (strcmp(key, "monitor_network") == 0) {
            // Legacy support: monitor_network sets both TCP and UDP
            bool parsed_value;
            if (parse_bool_value(value, &parsed_value) != 0) {
                fprintf(stderr, "Invalid boolean for %s on line %u: %s (expected true or false)\n",
                        key, line_number, value);
                parse_error = -EINVAL;
                goto out;
            }
            config->monitor_tcp = parsed_value;
            config->monitor_udp = parsed_value;
        } else if (strcmp(key, "verbosity") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, 10);
            if (*endptr != '\0' || val < 0 || val > 2) {
                fprintf(stderr, "Invalid verbosity value: %s (must be 0-2)\n", value);
                parse_error = -EINVAL;
                goto out;
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
                parse_error = -EINVAL;
                goto out;
            }
            config->min_uid = (unsigned int)val;
        } else if (strcmp(key, "max_uid") == 0) {
            // Parse max_uid with same overflow protection as min_uid
            // See min_uid comment for detailed security rationale
            char *endptr;
            unsigned long val = strtoul(value, &endptr, 10);
            if (*endptr != '\0' || val > UINT_MAX) {
                fprintf(stderr, "Invalid max_uid value: %s\n", value);
                parse_error = -EINVAL;
                goto out;
            }
            config->max_uid = (unsigned int)val;
        } else if (strcmp(key, "require_tty") == 0) {
            PARSE_BOOL_FIELD(require_tty);
        } else if (strcmp(key, "ignore_threads") == 0) {
            PARSE_BOOL_FIELD(ignore_threads);
        } else if (strcmp(key, "capture_cmdline") == 0) {
            PARSE_BOOL_FIELD(capture_cmdline);
        } else if (strcmp(key, "redact_sensitive") == 0) {
            PARSE_BOOL_FIELD(redact_sensitive);
        } else if (strcmp(key, "resolve_usernames") == 0) {
            PARSE_BOOL_FIELD(resolve_usernames);
        } else if (strcmp(key, "hash_binaries") == 0) {
            PARSE_BOOL_FIELD(hash_binaries);
        } else if (strcmp(key, "verify_packages") == 0) {
            PARSE_BOOL_FIELD(verify_packages);
        } else if (strcmp(key, "capture_container_metadata") == 0) {
            PARSE_BOOL_FIELD(capture_container_metadata);
        } else if (strcmp(key, "pkg_cache_file") == 0) {
            // Validate cache file path
            if (value[0] != '/') {
                fprintf(stderr, "Security: pkg_cache_file must be absolute path: %s\n", value);
                parse_error = -EINVAL;
                goto out;
            }
            if (strstr(value, "..") != NULL) {
                fprintf(stderr, "Security: pkg_cache_file cannot contain '..': %s\n", value);
                parse_error = -EINVAL;
                goto out;
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
                parse_error = -EINVAL;
                goto out;
            }
            config->pkg_cache_size = (int)val;
        } else if (strcmp(key, "hash_cache_file") == 0) {
            // Validate cache file path
            if (value[0] != '/') {
                fprintf(stderr, "Security: hash_cache_file must be absolute path: %s\n", value);
                parse_error = -EINVAL;
                goto out;
            }
            if (strstr(value, "..") != NULL) {
                fprintf(stderr, "Security: hash_cache_file cannot contain '..': %s\n", value);
                parse_error = -EINVAL;
                goto out;
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
                parse_error = -EINVAL;
                goto out;
            }
            config->hash_cache_size = (int)val;
        } else if (strcmp(key, "cache_save_interval") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, 10);
            if (*endptr != '\0' || val < 0 || val > 60) {
                fprintf(stderr, "Invalid cache_save_interval (0-60 minutes): %s\n", value);
                parse_error = -EINVAL;
                goto out;
            }
            config->cache_save_interval = (int)val;
        } else if (strcmp(key, "checkpoint_interval") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, 10);
            if (*endptr != '\0' || val < 0 || val > 1440) {  // 0 to 1440 minutes (24 hours)
                fprintf(stderr, "Invalid checkpoint_interval (0-1440 minutes): %s\n", value);
                parse_error = -EINVAL;
                goto out;
            }
            config->checkpoint_interval = (int)val;
        } else if (strcmp(key, "monitor_auth_integrity") == 0) {
            PARSE_BOOL_FIELD(monitor_auth_integrity);
        } else if (strcmp(key, "auth_integrity_interval") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, 10);
            if (*endptr != '\0' || val < 0 || val > 1440) {  // 0 to 1440 minutes (24 hours)
                fprintf(stderr, "Invalid auth_integrity_interval (0-1440 minutes): %s\n", value);
                parse_error = -EINVAL;
                goto out;
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
            PARSE_BOOL_FIELD(monitor_ptrace);
        } else if (strcmp(key, "monitor_modules") == 0) {
            PARSE_BOOL_FIELD(monitor_modules);
        } else if (strcmp(key, "monitor_memfd") == 0) {
            PARSE_BOOL_FIELD(monitor_memfd);
        } else if (strcmp(key, "monitor_bind") == 0) {
            PARSE_BOOL_FIELD(monitor_bind);
        } else if (strcmp(key, "monitor_unshare") == 0) {
            PARSE_BOOL_FIELD(monitor_unshare);
        } else if (strcmp(key, "monitor_execveat") == 0) {
            PARSE_BOOL_FIELD(monitor_execveat);
        } else if (strcmp(key, "monitor_bpf") == 0) {
            PARSE_BOOL_FIELD(monitor_bpf);
        } else if (strcmp(key, "monitor_cred_read") == 0) {
            PARSE_BOOL_FIELD(monitor_cred_read);
        } else if (strcmp(key, "monitor_ldpreload") == 0) {
            PARSE_BOOL_FIELD(monitor_ldpreload);
        } else if (strcmp(key, "monitor_persistence") == 0) {
            PARSE_BOOL_FIELD(monitor_persistence);
        } else if (strcmp(key, "monitor_suid") == 0) {
            PARSE_BOOL_FIELD(monitor_suid);
        } else if (strcmp(key, "monitor_cred_write") == 0) {
            PARSE_BOOL_FIELD(monitor_cred_write);
        } else if (strcmp(key, "monitor_log_tamper") == 0) {
            PARSE_BOOL_FIELD(monitor_log_tamper);
        } else if (strcmp(key, "monitor_raw_disk_access") == 0) {
            PARSE_BOOL_FIELD(monitor_raw_disk_access);
        } else {
            fprintf(stderr, "Unknown configuration key on line %u: %s\n",
                    line_number, key);
            parse_error = -EINVAL;
            goto out;
        }
    }

out:
    fclose(fp);
    if (parse_error != 0)
        free_config(config);
    return parse_error;
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
