// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// Authentication integrity monitoring - periodic validation of critical auth files

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/stat.h>
#include "authcheck.h"
#include "filehash.h"
#include "pkgcache.h"
#include "logger.h"

// Critical files to monitor
// Binaries: sshd, sudo, login, linmond (self-check)
// Configs: PAM configs, sshd_config, sudoers
static const char *critical_files[] = {
    // Authentication binaries
    "/usr/sbin/sshd",
    "/usr/bin/sudo",
    "/bin/login",
    "/usr/local/sbin/linmond",  // Self-check

    // PAM configuration
    "/etc/pam.d/sshd",
    "/etc/pam.d/sudo",
    "/etc/pam.d/common-auth",     // Ubuntu
    "/etc/pam.d/system-auth",     // RHEL/Rocky

    // SSH configuration
    "/etc/ssh/sshd_config",

    // Sudo configuration
    "/etc/sudoers",

    NULL  // Sentinel
};

static bool verify_packages_enabled = false;

void authcheck_init(bool verify_packages)
{
    verify_packages_enabled = verify_packages;
}

// Log authentication integrity violation to JSON and syslog
static void log_auth_integrity_violation(const char *file_path,
                                         const char *actual_hash,
                                         const char *package_name,
                                         bool modified,
                                         bool from_package)
{
    char timestamp[64];
    struct timespec ts;
    struct tm tm_info;
    char hostname[256];

    // Format timestamp
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm_info);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", &tm_info);
    snprintf(timestamp + strlen(timestamp), sizeof(timestamp) - strlen(timestamp),
             ".%03ldZ", ts.tv_nsec / 1000000);

    // Get hostname
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strncpy(hostname, "unknown", sizeof(hostname));
        hostname[sizeof(hostname) - 1] = '\0';
    }

    // Determine severity and verdict
    const char *severity;
    const char *verdict;

    if (!from_package) {
        severity = "CRITICAL";
        verdict = "not_in_package_database";
    } else if (modified) {
        severity = "CRITICAL";
        verdict = "modified_after_install";
    } else {
        severity = "WARNING";
        verdict = "hash_mismatch";
    }

    // Log to syslog (persistent, harder to delete than JSON)
    syslog(LOG_CRIT, "SECURITY ALERT: Authentication file integrity violation - "
                     "file=%s verdict=%s package=%s sha256=%s",
           file_path, verdict,
           from_package ? package_name : "none",
           actual_hash);

    // Log to JSON
    FILE *log_fp = logger_get_fp();
    if (!log_fp)
        return;

    pthread_mutex_t *mutex = logger_get_mutex();
    if (mutex) pthread_mutex_lock(mutex);

    // Get sequence number
    uint64_t seq = logger_get_sequence() + 1;

    fprintf(log_fp, "{\"seq\":%lu,"
                   "\"timestamp\":\"%s\","
                   "\"hostname\":\"%s\","
                   "\"type\":\"auth_integrity_violation\","
                   "\"severity\":\"%s\","
                   "\"attack_technique\":\"T1556.003/T1556.004\","
                   "\"attack_name\":\"Modify Authentication Process\","
                   "\"file_path\":\"%s\","
                   "\"verdict\":\"%s\"",
           seq, timestamp, hostname, severity, file_path, verdict);

    if (from_package) {
        fprintf(log_fp, ",\"package\":\"%s\",\"modified\":%s",
                package_name, modified ? "true" : "false");
    } else {
        fprintf(log_fp, ",\"package\":null");
    }

    fprintf(log_fp, ",\"sha256\":\"%s\"}\n", actual_hash);
    fflush(log_fp);

    if (mutex) pthread_mutex_unlock(mutex);
}

int authcheck_verify_all(void)
{
    int violations = 0;
    char hash[SHA256_HEX_LEN];
    struct pkg_info pkg;

    for (int i = 0; critical_files[i] != NULL; i++) {
        const char *path = critical_files[i];

        // Check if file exists
        struct stat st;
        if (stat(path, &st) != 0) {
            // File doesn't exist - this is OK for distro-specific files
            // (e.g., /etc/pam.d/system-auth only on RHEL, not Ubuntu)
            continue;
        }

        // Calculate hash
        if (!filehash_calculate(path, hash, sizeof(hash))) {
            // Hash calculation failed - log warning but continue
            syslog(LOG_WARNING, "authcheck: failed to hash %s", path);
            continue;
        }

        // If package verification is disabled, we can only log the hash
        // (no baseline to compare against)
        if (!verify_packages_enabled)
            continue;

        // Look up package information
        int ret = pkgcache_lookup(path, &pkg);
        if (ret != 0) {
            // Package lookup failed - treat as warning
            syslog(LOG_WARNING, "authcheck: failed to lookup package for %s", path);
            continue;
        }

        // Check for violations
        if (!pkg.from_package) {
            // Critical file is not from package - VERY suspicious
            log_auth_integrity_violation(path, hash, "", false, false);
            violations++;
        } else if (pkg.modified) {
            // File has been modified since package installation
            log_auth_integrity_violation(path, hash, pkg.package, true, true);
            violations++;
        }
        // If from_package && !modified: All good, no logging (sparse events)
    }

    return violations;
}
