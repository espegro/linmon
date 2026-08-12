// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// File hashing - SHA256 calculation with persistent caching

#ifndef __LINMON_FILEHASH_H
#define __LINMON_FILEHASH_H

#include <sys/types.h>
#include <stdbool.h>

#define SHA256_HEX_LEN 65  // 64 chars + null terminator
#define HASH_CACHE_DEFAULT_PATH "/var/cache/linmon/hashes.cache"
#define HASH_CACHE_DEFAULT_SIZE 10000

// Initialize file hash cache
// cache_file: path to persistent cache file (NULL for default)
// max_entries: maximum cache entries (0 for default)
int filehash_init(const char *cache_file, int max_entries);

// Cleanup and save file hash cache
void filehash_cleanup(void);

// Save cache to disk (for periodic saves)
// Returns 0 on success, negative errno on error
int filehash_save(void);

// Load cache from disk
// Returns number of entries loaded, or negative errno on error
int filehash_load(void);

// Get cache statistics
void filehash_stats(unsigned long *hits, unsigned long *misses,
                    unsigned long *entries, unsigned long *recomputes);

// Calculate SHA256 hash of file (cached based on inode/mtime/size)
// Returns true on success, false on error
// Thread-safe
bool filehash_calculate(const char *path, char *hash_out, size_t hash_size);

// Recalculate SHA256 from an already-open regular-file descriptor. Uses pread()
// so the caller's file offset is unchanged, and updates the cache under cache_key.
// Unlike filehash_calculate(), this always reads the file contents.
bool filehash_calculate_fd(int fd, const char *cache_key,
                           char *hash_out, size_t hash_size);

#endif /* __LINMON_FILEHASH_H */
