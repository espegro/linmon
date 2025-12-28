// SPDX-License-Identifier: GPL-2.0
// Package cache implementation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include "pkgcache.h"

// Cache entry structure
struct cache_entry {
    char path[PKG_PATH_MAX];
    ino_t inode;
    time_t mtime;
    time_t cached_at;  // When this entry was cached (for TTL)
    char package[PKG_NAME_MAX];
    bool from_package;
    struct cache_entry *next;  // Hash chain
};

// Simple hash table
#define HASH_BUCKETS 4096

// Cache TTL in seconds (24 hours)
// After this time, entries are re-queried even if inode/mtime match
// This ensures package upgrades are detected even if binary has same inode
#define CACHE_TTL (24 * 3600)

static struct cache_entry *hash_table[HASH_BUCKETS];
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static char cache_file_path[PKG_PATH_MAX] = PKG_CACHE_DEFAULT_PATH;
static int max_cache_entries = PKG_CACHE_DEFAULT_SIZE;
static int current_entries = 0;

// Statistics
static unsigned long stat_hits = 0;
static unsigned long stat_misses = 0;
static unsigned long stat_revalidations = 0;

// Package manager type
enum pkg_manager {
    PKG_UNKNOWN,
    PKG_DPKG,    // Debian/Ubuntu
    PKG_RPM      // RHEL/Rocky/Fedora
};

static enum pkg_manager detected_pkg_manager = PKG_UNKNOWN;

// UsrMerge detection: -1=unknown, 0=no, 1=yes
// Modern Debian/Ubuntu use /bin -> /usr/bin symlinks (UsrMerge)
static int usrmerge_detected = -1;

// Detect if system uses UsrMerge (/bin -> /usr/bin symlink)
static void detect_usrmerge(void)
{
	struct stat st;

	if (usrmerge_detected != -1)
		return;  // Already detected

	// Check if /bin is a symlink (UsrMerge enabled)
	if (lstat("/bin", &st) == 0 && S_ISLNK(st.st_mode)) {
		usrmerge_detected = 1;
	} else {
		usrmerge_detected = 0;
	}
}

// Normalize path for UsrMerge systems
// On UsrMerge systems, /usr/bin/foo might not be in dpkg database,
// but /bin/foo is (because packages install to /bin, which is symlinked)
// Returns normalized path in buf, or original path if no normalization needed
static const char *normalize_usrmerge_path(const char *path, char *buf, size_t buflen)
{
	detect_usrmerge();

	if (usrmerge_detected != 1)
		return path;  // Not UsrMerge, use original path

	// Convert /usr/bin/* -> /bin/*
	if (strncmp(path, "/usr/bin/", 9) == 0) {
		snprintf(buf, buflen, "/bin%s", path + 8);
		return buf;
	}

	// Convert /usr/sbin/* -> /sbin/*
	if (strncmp(path, "/usr/sbin/", 10) == 0) {
		snprintf(buf, buflen, "/sbin%s", path + 9);
		return buf;
	}

	// Convert /usr/lib/* -> /lib/* (libraries)
	if (strncmp(path, "/usr/lib/", 9) == 0) {
		snprintf(buf, buflen, "/lib%s", path + 8);
		return buf;
	}

	// Convert /usr/lib64/* -> /lib64/* (RHEL x86_64)
	if (strncmp(path, "/usr/lib64/", 11) == 0) {
		snprintf(buf, buflen, "/lib64%s", path + 10);
		return buf;
	}

	return path;  // No conversion needed
}

// Simple hash function (djb2)
static unsigned int hash_path(const char *path)
{
    unsigned int hash = 5381;
    int c;

    while ((c = *path++))
        hash = ((hash << 5) + hash) + c;

    return hash % HASH_BUCKETS;
}

// Detect package manager
static void detect_pkg_manager(void)
{
    struct stat st;

    if (stat("/usr/bin/dpkg", &st) == 0) {
        detected_pkg_manager = PKG_DPKG;
    } else if (stat("/usr/bin/rpm", &st) == 0) {
        detected_pkg_manager = PKG_RPM;
    } else {
        detected_pkg_manager = PKG_UNKNOWN;
    }
}

// Escape path for safe shell use (prevent command injection)
// Escapes single quotes: ' becomes '\''
// Returns 0 on success, -1 if output buffer too small or path contains invalid chars
static int escape_path_for_shell(const char *path, char *escaped, size_t escaped_size)
{
    size_t j = 0;

    for (size_t i = 0; path[i] != '\0'; i++) {
        char c = path[i];

        // Reject paths with newlines or null bytes (shouldn't happen but be safe)
        if (c == '\n' || c == '\r')
            return -1;

        if (c == '\'') {
            // Replace ' with '\'' (close quote, escaped quote, reopen quote)
            if (j + 4 >= escaped_size)
                return -1;
            escaped[j++] = '\'';
            escaped[j++] = '\\';
            escaped[j++] = '\'';
            escaped[j++] = '\'';
        } else {
            if (j + 1 >= escaped_size)
                return -1;
            escaped[j++] = c;
        }
    }

    escaped[j] = '\0';
    return 0;
}

// Helper to try package manager query with a specific path
// Returns 0 on success with package name in buf, -1 on failure
static int try_package_query(const char *query_path, char *buf, size_t buflen)
{
	FILE *fp;
	char escaped_path[PKG_PATH_MAX * 4];
	char cmd[PKG_PATH_MAX * 4 + 64];
	char line[256];
	int ret = -1;

	// Escape path to prevent command injection
	if (escape_path_for_shell(query_path, escaped_path, sizeof(escaped_path)) != 0)
		return -1;

	// Build command based on package manager
	if (detected_pkg_manager == PKG_DPKG) {
		snprintf(cmd, sizeof(cmd), "/usr/bin/dpkg -S '%s' 2>/dev/null", escaped_path);
	} else if (detected_pkg_manager == PKG_RPM) {
		snprintf(cmd, sizeof(cmd), "/usr/bin/rpm -qf '%s' 2>/dev/null", escaped_path);
	} else {
		return -1;
	}

	fp = popen(cmd, "r");
	if (!fp)
		return -1;

	if (fgets(line, sizeof(line), fp)) {
		// Remove trailing newline
		size_t len = strlen(line);
		if (len > 0 && line[len - 1] == '\n')
			line[len - 1] = '\0';

		if (detected_pkg_manager == PKG_DPKG) {
			// Parse "package: /path" format
			char *colon = strchr(line, ':');
			if (colon) {
				*colon = '\0';
				// Handle diversion messages
				if (strncmp(line, "diversion", 9) != 0) {
					strncpy(buf, line, buflen - 1);
					buf[buflen - 1] = '\0';
					ret = 0;
				}
			}
		} else if (detected_pkg_manager == PKG_RPM) {
			// Check if it's an error message
			if (strncmp(line, "file ", 5) != 0 &&
			    strncmp(line, "error:", 6) != 0) {
				// Remove version suffix (keep only package name)
				// e.g., "coreutils-8.32-1.el9" -> "coreutils"
				char *dash = line;
				char *last_dash = NULL;
				while ((dash = strchr(dash, '-')) != NULL) {
					// Check if followed by digit (version)
					if (dash[1] >= '0' && dash[1] <= '9') {
						last_dash = dash;
						break;
					}
					dash++;
				}
				if (last_dash)
					*last_dash = '\0';

				strncpy(buf, line, buflen - 1);
				buf[buflen - 1] = '\0';
				ret = 0;
			}
		}
	}

	pclose(fp);
	return ret;
}

// Look up package for a file using package manager
// Returns package name in buf, or empty string if not from package
// Handles UsrMerge systems where /usr/bin/foo is hardlinked to /bin/foo
// but only /bin/foo is in the package database
static int query_package_manager(const char *path, char *buf, size_t buflen)
{
	char normalized_path[PKG_PATH_MAX];
	char realpath_buf[PKG_PATH_MAX];
	const char *query_path;
	int ret;

	buf[0] = '\0';

	if (detected_pkg_manager == PKG_UNKNOWN)
		return -ENOTSUP;

	// Strategy for UsrMerge compatibility:
	// 1. Try normalized path first (/usr/bin/foo -> /bin/foo on UsrMerge)
	// 2. If that fails, try original path
	// 3. If that fails, try realpath (resolves symlinks)

	// Try 1: Normalized path (handles UsrMerge)
	query_path = normalize_usrmerge_path(path, normalized_path, sizeof(normalized_path));
	ret = try_package_query(query_path, buf, buflen);
	if (ret == 0)
		return 0;  // Success

	// Try 2: Original path (if different from normalized)
	if (query_path != path) {
		ret = try_package_query(path, buf, buflen);
		if (ret == 0)
			return 0;  // Success
	}

	// Try 3: Realpath fallback (resolves symlinks, handles hardlinks)
	if (realpath(path, realpath_buf) != NULL) {
		// Only try if realpath is different from both previous attempts
		if (strcmp(realpath_buf, path) != 0 &&
		    strcmp(realpath_buf, query_path) != 0) {
			ret = try_package_query(realpath_buf, buf, buflen);
			if (ret == 0)
				return 0;  // Success
		}
	}

	// All attempts failed
	return -1;
}

// Find or create cache entry
static struct cache_entry *cache_find(const char *path)
{
    unsigned int h = hash_path(path);
    struct cache_entry *entry = hash_table[h];

    while (entry) {
        if (strcmp(entry->path, path) == 0)
            return entry;
        entry = entry->next;
    }

    return NULL;
}

// Add entry to cache
static struct cache_entry *cache_add(const char *path, ino_t inode,
                                      time_t mtime, const char *package,
                                      bool from_package)
{
    unsigned int h;
    struct cache_entry *entry;

    // Check capacity
    if (current_entries >= max_cache_entries) {
        // Simple eviction: don't add new entries when full
        // A more sophisticated LRU could be implemented
        return NULL;
    }

    entry = calloc(1, sizeof(*entry));
    if (!entry)
        return NULL;

    strncpy(entry->path, path, PKG_PATH_MAX - 1);
    entry->path[PKG_PATH_MAX - 1] = '\0';
    entry->inode = inode;
    entry->mtime = mtime;
    entry->cached_at = time(NULL);  // Set cache timestamp
    strncpy(entry->package, package, PKG_NAME_MAX - 1);
    entry->package[PKG_NAME_MAX - 1] = '\0';
    entry->from_package = from_package;

    h = hash_path(path);
    entry->next = hash_table[h];
    hash_table[h] = entry;
    current_entries++;

    return entry;
}

// Update existing entry
static void cache_update(struct cache_entry *entry, ino_t inode,
                         time_t mtime, const char *package, bool from_package)
{
    entry->inode = inode;
    entry->mtime = mtime;
    entry->cached_at = time(NULL);  // Update cache timestamp
    strncpy(entry->package, package, PKG_NAME_MAX - 1);
    entry->package[PKG_NAME_MAX - 1] = '\0';
    entry->from_package = from_package;
}

int pkgcache_init(const char *cache_file, int max_entries)
{
    detect_pkg_manager();

    if (cache_file && strlen(cache_file) < PKG_PATH_MAX) {
        strncpy(cache_file_path, cache_file, PKG_PATH_MAX - 1);
        cache_file_path[PKG_PATH_MAX - 1] = '\0';
    }

    if (max_entries > 0)
        max_cache_entries = max_entries;

    // Initialize hash table
    memset(hash_table, 0, sizeof(hash_table));

    // Try to load existing cache
    pkgcache_load();

    return 0;
}

int pkgcache_lookup(const char *path, struct pkg_info *info)
{
    struct stat st;
    struct cache_entry *entry;
    char package[PKG_NAME_MAX];
    bool needs_lookup = false;
    int ret;

    if (!path || !info)
        return -EINVAL;

    // Initialize output
    memset(info, 0, sizeof(*info));

    // Get current file stats
    if (stat(path, &st) != 0) {
        return -errno;
    }

    // Only cache regular files
    if (!S_ISREG(st.st_mode)) {
        info->from_package = false;
        return 0;
    }

    pthread_mutex_lock(&cache_mutex);

    entry = cache_find(path);
    if (entry) {
        time_t now = time(NULL);

        // Check if file has changed (inode or mtime) OR cache expired (TTL)
        if (entry->inode != st.st_ino || entry->mtime != st.st_mtime ||
            (now - entry->cached_at) > CACHE_TTL) {
            // File changed or cache expired - need to revalidate
            needs_lookup = true;
            stat_revalidations++;
        } else {
            // Cache hit
            stat_hits++;
            strncpy(info->package, entry->package, PKG_NAME_MAX - 1);
            info->package[PKG_NAME_MAX - 1] = '\0';
            info->from_package = entry->from_package;
            info->modified = false;
            pthread_mutex_unlock(&cache_mutex);
            return 0;
        }
    } else {
        // Cache miss
        stat_misses++;
        needs_lookup = true;
    }

    pthread_mutex_unlock(&cache_mutex);

    if (needs_lookup) {
        // Query package manager (outside mutex - this is slow)
        ret = query_package_manager(path, package, sizeof(package));

        pthread_mutex_lock(&cache_mutex);

        if (ret == 0 && package[0] != '\0') {
            // File belongs to a package
            info->from_package = true;
            strncpy(info->package, package, PKG_NAME_MAX - 1);
            info->package[PKG_NAME_MAX - 1] = '\0';

            // Check if this was previously from a different package
            // or if it's a revalidation (file was modified)
            if (entry) {
                if (strcmp(entry->package, package) != 0) {
                    // Package changed - suspicious!
                    info->modified = true;
                }
                cache_update(entry, st.st_ino, st.st_mtime, package, true);
            } else {
                cache_add(path, st.st_ino, st.st_mtime, package, true);
            }
        } else {
            // File not from a package
            info->from_package = false;
            info->package[0] = '\0';

            // If it was previously from a package, it's been replaced!
            if (entry && entry->from_package) {
                info->modified = true;
            }

            if (entry) {
                cache_update(entry, st.st_ino, st.st_mtime, "", false);
            } else {
                cache_add(path, st.st_ino, st.st_mtime, "", false);
            }
        }

        pthread_mutex_unlock(&cache_mutex);
    }

    return 0;
}

int pkgcache_save(void)
{
    FILE *fp;
    char tmp_path[PKG_PATH_MAX + 8];
    int i;

    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", cache_file_path);

    fp = fopen(tmp_path, "w");
    if (!fp)
        return -errno;

    // Set restrictive permissions on cache file (0600 = rw-------)
    // This prevents information leakage of system paths
    if (fchmod(fileno(fp), 0600) != 0) {
        int saved_errno = errno;
        fclose(fp);
        unlink(tmp_path);
        return -saved_errno;
    }

    // Write header
    fprintf(fp, "# LinMon package cache v2\n");
    fprintf(fp, "# path|inode|mtime|cached_at|package|from_pkg\n");

    pthread_mutex_lock(&cache_mutex);

    for (i = 0; i < HASH_BUCKETS; i++) {
        struct cache_entry *entry = hash_table[i];
        while (entry) {
            fprintf(fp, "%s|%lu|%ld|%ld|%s|%d\n",
                    entry->path,
                    (unsigned long)entry->inode,
                    (long)entry->mtime,
                    (long)entry->cached_at,
                    entry->package,
                    entry->from_package ? 1 : 0);
            entry = entry->next;
        }
    }

    pthread_mutex_unlock(&cache_mutex);

    fclose(fp);

    // Atomic rename
    if (rename(tmp_path, cache_file_path) != 0) {
        unlink(tmp_path);
        return -errno;
    }

    return 0;
}

int pkgcache_load(void)
{
    FILE *fp;
    char line[PKG_PATH_MAX + PKG_NAME_MAX + 64];
    int loaded = 0;

    fp = fopen(cache_file_path, "r");
    if (!fp) {
        if (errno == ENOENT)
            return 0;  // No cache file yet, that's OK
        return -errno;
    }

    pthread_mutex_lock(&cache_mutex);

    while (fgets(line, sizeof(line), fp)) {
        char path[PKG_PATH_MAX];
        unsigned long inode;
        long mtime, cached_at;
        char package[PKG_NAME_MAX];
        int from_pkg;

        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n')
            continue;

        // Try v2 format first: path|inode|mtime|cached_at|package|from_pkg
        if (sscanf(line, "%255[^|]|%lu|%ld|%ld|%63[^|]|%d",
                   path, &inode, &mtime, &cached_at, package, &from_pkg) >= 5) {
            // Handle empty package field
            if (strcmp(package, "|") == 0 || package[0] == '\0') {
                package[0] = '\0';
            }
            struct cache_entry *entry = cache_add(path, (ino_t)inode, (time_t)mtime, package, from_pkg != 0);
            if (entry) {
                entry->cached_at = (time_t)cached_at;  // Restore cached timestamp
            }
            loaded++;
        }
        // Try v2 format with empty package: path|inode|mtime|cached_at||from_pkg
        else if (sscanf(line, "%255[^|]|%lu|%ld|%ld||%d",
                          path, &inode, &mtime, &cached_at, &from_pkg) == 5) {
            struct cache_entry *entry = cache_add(path, (ino_t)inode, (time_t)mtime, "", from_pkg != 0);
            if (entry) {
                entry->cached_at = (time_t)cached_at;
            }
            loaded++;
        }
        // Fallback to v1 format: path|inode|mtime|package|from_pkg (backward compat)
        else if (sscanf(line, "%255[^|]|%lu|%ld|%63[^|]|%d",
                   path, &inode, &mtime, package, &from_pkg) >= 4) {
            // Handle empty package field
            if (strcmp(package, "|") == 0 || package[0] == '\0') {
                package[0] = '\0';
            }
            // No cached_at in v1 - will be set to current time by cache_add
            cache_add(path, (ino_t)inode, (time_t)mtime, package, from_pkg != 0);
            loaded++;
        }
        // Fallback to v1 format with empty package: path|inode|mtime||from_pkg
        else if (sscanf(line, "%255[^|]|%lu|%ld||%d",
                          path, &inode, &mtime, &from_pkg) == 4) {
            cache_add(path, (ino_t)inode, (time_t)mtime, "", from_pkg != 0);
            loaded++;
        }
    }

    pthread_mutex_unlock(&cache_mutex);

    fclose(fp);

    return loaded;
}

void pkgcache_stats(unsigned long *hits, unsigned long *misses,
                    unsigned long *entries, unsigned long *revalidations)
{
    pthread_mutex_lock(&cache_mutex);

    if (hits) *hits = stat_hits;
    if (misses) *misses = stat_misses;
    if (entries) *entries = current_entries;
    if (revalidations) *revalidations = stat_revalidations;

    pthread_mutex_unlock(&cache_mutex);
}

void pkgcache_cleanup(void)
{
    int i;

    // Save before cleanup
    pkgcache_save();

    pthread_mutex_lock(&cache_mutex);

    for (i = 0; i < HASH_BUCKETS; i++) {
        struct cache_entry *entry = hash_table[i];
        while (entry) {
            struct cache_entry *next = entry->next;
            free(entry);
            entry = next;
        }
        hash_table[i] = NULL;
    }

    current_entries = 0;
    stat_hits = 0;
    stat_misses = 0;
    stat_revalidations = 0;

    pthread_mutex_unlock(&cache_mutex);
}
