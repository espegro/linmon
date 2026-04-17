// SPDX-License-Identifier: GPL-2.0-or-later
// Safe file operations with symlink protection

#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

// Safe file opening with symlink protection
// Returns NULL on error (errno set), includes ELOOP for symlink detection
FILE *safe_fopen(const char *path, const char *mode, mode_t perms);

// Open an existing file read-only without following symlinks.
// Returns NULL on error (errno set), including ELOOP for symlink detection.
FILE *safe_fopen_readonly(const char *path, struct stat *st_out);

#endif
