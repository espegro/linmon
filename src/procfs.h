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

// Read SUDO_UID and SUDO_USER from /proc/<pid>/environ
// Returns true if SUDO_UID was found (process running via sudo)
// sudo_uid: output, the original UID before sudo
// sudo_user: output buffer for username, sudo_user_len: buffer size
bool procfs_read_sudo_info(pid_t pid, uid_t *sudo_uid, char *sudo_user, size_t sudo_user_len);

#endif /* __LINMON_PROCFS_H */
