// SPDX-License-Identifier: GPL-2.0
// Event logging interface

#ifndef __LINMON_LOGGER_H
#define __LINMON_LOGGER_H

#include <stdbool.h>
#include "../bpf/common.h"

// Initialize logger with output file
int logger_init(const char *log_file);

// Set enrichment options
void logger_set_enrichment(bool resolve_usernames, bool hash_binaries);

// Log a process event
int logger_log_process_event(const struct process_event *event);

// Log a file event
int logger_log_file_event(const struct file_event *event);

// Log a network event
int logger_log_network_event(const struct network_event *event);

// Log a privilege escalation event
int logger_log_privilege_event(const struct privilege_event *event);

// Cleanup logger
void logger_cleanup(void);

#endif /* __LINMON_LOGGER_H */
