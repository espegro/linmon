// SPDX-License-Identifier: GPL-2.0-or-later
// Safe file operations with symlink protection

#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <sys/types.h>

// Safe file opening with symlink protection
// Returns NULL on error (errno set), includes ELOOP for symlink detection
FILE *safe_fopen(const char *path, const char *mode, mode_t perms);

#endif
