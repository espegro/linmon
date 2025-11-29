// SPDX-License-Identifier: GPL-2.0
// Process filesystem utilities

#ifndef __LINMON_PROCFS_H
#define __LINMON_PROCFS_H

#include <sys/types.h>
#include <stdbool.h>

// Read process command line from /proc/<pid>/cmdline
// Returns true on success, false on error
// Replaces null bytes with spaces, caps at max_len
bool procfs_read_cmdline(pid_t pid, char *buf, size_t max_len);

#endif /* __LINMON_PROCFS_H */
