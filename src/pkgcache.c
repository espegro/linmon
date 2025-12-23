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

#include "pkgcache.h"

// Cache entry structure
struct cache_entry {
    char path[PKG_PATH_MAX];
    ino_t inode;
    time_t mtime;
    char package[PKG_NAME_MAX];
    bool from_package;
    struct cache_entry *next;  // Hash chain
};

// Simple hash table
#define HASH_BUCKETS 4096

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

// Look up package for a file using package manager
// Returns package name in buf, or empty string if not from package
static int query_package_manager(const char *path, char *buf, size_t buflen)
{
    FILE *fp;
    char cmd[PKG_PATH_MAX + 64];
    char line[256];
    int ret = -1;

    buf[0] = '\0';

    if (detected_pkg_manager == PKG_UNKNOWN)
        return -ENOTSUP;

    // Build command based on package manager
    if (detected_pkg_manager == PKG_DPKG) {
        // dpkg -S /path/to/file
        // Output: "package: /path/to/file" or error
        snprintf(cmd, sizeof(cmd), "dpkg -S '%s' 2>/dev/null", path);
    } else if (detected_pkg_manager == PKG_RPM) {
        // rpm -qf /path/to/file
        // Output: "package-version" or error
        snprintf(cmd, sizeof(cmd), "rpm -qf '%s' 2>/dev/null", path);
    } else {
        return -ENOTSUP;
    }

    fp = popen(cmd, "r");
    if (!fp)
        return -errno;

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
    entry->inode = inode;
    entry->mtime = mtime;
    strncpy(entry->package, package, PKG_NAME_MAX - 1);
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
    strncpy(entry->package, package, PKG_NAME_MAX - 1);
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
        // Check if file has changed (inode or mtime)
        if (entry->inode != st.st_ino || entry->mtime != st.st_mtime) {
            // File changed - need to revalidate
            needs_lookup = true;
            stat_revalidations++;
        } else {
            // Cache hit
            stat_hits++;
            strncpy(info->package, entry->package, PKG_NAME_MAX - 1);
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

    // Write header
    fprintf(fp, "# LinMon package cache v1\n");
    fprintf(fp, "# path|inode|mtime|package|from_pkg\n");

    pthread_mutex_lock(&cache_mutex);

    for (i = 0; i < HASH_BUCKETS; i++) {
        struct cache_entry *entry = hash_table[i];
        while (entry) {
            fprintf(fp, "%s|%lu|%ld|%s|%d\n",
                    entry->path,
                    (unsigned long)entry->inode,
                    (long)entry->mtime,
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
        long mtime;
        char package[PKG_NAME_MAX];
        int from_pkg;

        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n')
            continue;

        // Parse line
        if (sscanf(line, "%255[^|]|%lu|%ld|%63[^|]|%d",
                   path, &inode, &mtime, package, &from_pkg) >= 4) {
            // Handle empty package field
            if (strcmp(package, "|") == 0 || package[0] == '\0') {
                package[0] = '\0';
            }
            cache_add(path, (ino_t)inode, (time_t)mtime, package, from_pkg != 0);
            loaded++;
        } else if (sscanf(line, "%255[^|]|%lu|%ld||%d",
                          path, &inode, &mtime, &from_pkg) == 4) {
            // Empty package field
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
