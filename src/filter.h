// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
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
// NUL-separated arguments, including a terminator for the final argument.
void filter_redact_argv(char *args, size_t length);

#endif /* __LINMON_FILTER_H */
