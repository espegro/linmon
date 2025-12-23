// SPDX-License-Identifier: GPL-2.0
// Package cache - tracks which binaries belong to system packages

#ifndef PKGCACHE_H
#define PKGCACHE_H

#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

// Maximum path length for cache entries (use system PATH_MAX)
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define PKG_PATH_MAX PATH_MAX
// Maximum package name length
#define PKG_NAME_MAX 64
// Default cache file path
#define PKG_CACHE_DEFAULT_PATH "/var/cache/linmon/packages.cache"
// Default cache size (max entries)
#define PKG_CACHE_DEFAULT_SIZE 10000
// Default save interval in seconds
#define PKG_CACHE_SAVE_INTERVAL 300  // 5 minutes

// Package info result
struct pkg_info {
    char package[PKG_NAME_MAX];  // Package name, empty string if not from package
    bool from_package;           // true if file belongs to a known package
    bool modified;               // true if file was modified since package install
};

// Initialize the package cache
// cache_file: path to persistent cache file (NULL for default)
// max_entries: maximum cache entries (0 for default)
// Returns 0 on success, negative errno on failure
int pkgcache_init(const char *cache_file, int max_entries);

// Look up package info for a binary
// path: absolute path to the binary
// info: output structure for package information
// Returns 0 on success, negative errno on failure
int pkgcache_lookup(const char *path, struct pkg_info *info);

// Save cache to disk
// Called periodically and on shutdown
// Returns 0 on success, negative errno on failure
int pkgcache_save(void);

// Load cache from disk
// Called at startup
// Returns 0 on success, negative errno on failure
int pkgcache_load(void);

// Get cache statistics
void pkgcache_stats(unsigned long *hits, unsigned long *misses,
                    unsigned long *entries, unsigned long *revalidations);

// Clean up and free resources
void pkgcache_cleanup(void);

#endif // PKGCACHE_H
