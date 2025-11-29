// SPDX-License-Identifier: GPL-2.0
// Event filtering and processing

#ifndef __LINMON_FILTER_H
#define __LINMON_FILTER_H

#include <stdbool.h>
#include "config.h"
#include "../bpf/common.h"

// Initialize filter with configuration
void filter_init(const struct linmon_config *config);

// Check if process should be logged based on name
bool filter_should_log_process(const char *comm);

// Check if file should be logged based on path
bool filter_should_log_file(const char *filename);

// Redact sensitive information from command line
void filter_redact_cmdline(char *cmdline, size_t size);

#endif /* __LINMON_FILTER_H */
