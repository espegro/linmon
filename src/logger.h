// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// Event logging interface

#ifndef __LINMON_LOGGER_H
#define __LINMON_LOGGER_H

#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include "../bpf/common.h"

// Initialize logger with output file
int logger_init(const char *log_file);

// Set enrichment options
void logger_set_enrichment(bool resolve_usernames, bool hash_binaries,
                           bool verify_packages, bool container_metadata);

// Configure built-in log rotation
// log_file: base path for rotation (e.g., "/var/log/linmon/events.json")
// max_size: rotate when file exceeds this size (bytes)
// max_files: number of rotated files to keep
void logger_set_rotation(const char *log_file, bool enabled,
                         unsigned long max_size, int max_files);

// Enable or disable syslog output for all events
// When enabled, all events are logged to syslog in addition to JSON file
void logger_set_syslog(bool enabled);

// Replace logger file pointer atomically (for config reload)
void logger_replace(FILE *new_fp);

// Log a process event
int logger_log_process_event(const struct process_event *event);

// Log a file event
int logger_log_file_event(const struct file_event *event);

// Log a network event
int logger_log_network_event(const struct network_event *event);

// Log a privilege escalation event
int logger_log_privilege_event(const struct privilege_event *event);

// Log a security monitoring event (MITRE ATT&CK detection)
int logger_log_security_event(const struct security_event *event);

// Log a persistence mechanism event (T1053, T1547)
int logger_log_persistence_event(const struct persistence_event *event);

// Get logger file pointer (for daemon lifecycle events)
FILE *logger_get_fp(void);

// Get logger mutex (for thread-safe access)
pthread_mutex_t *logger_get_mutex(void);

// Get current sequence number (for tamper detection)
uint64_t logger_get_sequence(void);

// Get total event count (for tamper detection)
unsigned long logger_get_event_count(void);

// Check if log file has been deleted and recover (T1070.001 detection)
// Returns: true if file was deleted and recovered, false otherwise
bool logger_check_file_deleted(void);

// Cleanup logger
void logger_cleanup(void);

#endif /* __LINMON_LOGGER_H */
