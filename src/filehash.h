// SPDX-License-Identifier: GPL-2.0
// File hashing - SHA256 calculation with caching

#ifndef __LINMON_FILEHASH_H
#define __LINMON_FILEHASH_H

#include <sys/types.h>
#include <stdbool.h>

#define SHA256_HEX_LEN 65  // 64 chars + null terminator

// Initialize file hash cache
void filehash_init(void);

// Cleanup file hash cache
void filehash_cleanup(void);

// Calculate SHA256 hash of file (cached based on inode/mtime/size)
// Returns true on success, false on error
// Thread-safe
bool filehash_calculate(const char *path, char *hash_out, size_t hash_size);

#endif /* __LINMON_FILEHASH_H */
