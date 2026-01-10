// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// File hashing - SHA256 calculation with persistent caching

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "filehash.h"

#define HASH_BUCKETS 4096
#define READ_BUFFER_SIZE 8192
#define PATH_MAX_LEN 256

// Cache entry structure
struct hash_entry {
    char path[PATH_MAX_LEN];
    dev_t dev;
    ino_t ino;
    time_t mtime;
    off_t size;
    char hash[SHA256_HEX_LEN];
    unsigned long access_count;
    struct hash_entry *next;  // Hash chain
};

// Hash table
static struct hash_entry *hash_table[HASH_BUCKETS];
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static char cache_file_path[PATH_MAX_LEN] = HASH_CACHE_DEFAULT_PATH;
static int max_cache_entries = HASH_CACHE_DEFAULT_SIZE;
static int current_entries = 0;
static unsigned long global_access_counter = 0;

// Statistics
static unsigned long stat_hits = 0;
static unsigned long stat_misses = 0;
static unsigned long stat_recomputes = 0;

// Simple hash function (djb2)
static unsigned int hash_path(const char *path)
{
    unsigned int hash = 5381;
    int c;

    while ((c = *path++))
        hash = ((hash << 5) + hash) + c;

    return hash % HASH_BUCKETS;
}

// Find entry in cache by path
static struct hash_entry *cache_find(const char *path)
{
    unsigned int h = hash_path(path);
    struct hash_entry *entry = hash_table[h];

    while (entry) {
        if (strcmp(entry->path, path) == 0)
            return entry;
        entry = entry->next;
    }

    return NULL;
}

// Find LRU entry for eviction
static struct hash_entry **find_lru_entry(void)
{
    struct hash_entry **lru_ptr = NULL;
    unsigned long min_access = ULONG_MAX;

    for (int i = 0; i < HASH_BUCKETS; i++) {
        struct hash_entry **entry_ptr = &hash_table[i];
        while (*entry_ptr) {
            if ((*entry_ptr)->access_count < min_access) {
                min_access = (*entry_ptr)->access_count;
                lru_ptr = entry_ptr;
            }
            entry_ptr = &(*entry_ptr)->next;
        }
    }

    return lru_ptr;
}

// Add entry to cache
static struct hash_entry *cache_add(const char *path, dev_t dev, ino_t ino,
                                     time_t mtime, off_t size, const char *hash)
{
    struct hash_entry *entry;
    unsigned int h;

    // Check capacity - evict LRU if full
    if (current_entries >= max_cache_entries) {
        struct hash_entry **lru_ptr = find_lru_entry();
        if (lru_ptr && *lru_ptr) {
            struct hash_entry *lru = *lru_ptr;
            *lru_ptr = lru->next;
            free(lru);
            current_entries--;
        }
    }

    entry = calloc(1, sizeof(*entry));
    if (!entry)
        return NULL;

    strncpy(entry->path, path, PATH_MAX_LEN - 1);
    entry->path[PATH_MAX_LEN - 1] = '\0';
    entry->dev = dev;
    entry->ino = ino;
    entry->mtime = mtime;
    entry->size = size;
    strncpy(entry->hash, hash, SHA256_HEX_LEN - 1);
    entry->hash[SHA256_HEX_LEN - 1] = '\0';
    entry->access_count = ++global_access_counter;

    h = hash_path(path);
    entry->next = hash_table[h];
    hash_table[h] = entry;
    current_entries++;

    return entry;
}

// Update existing entry
static void cache_update(struct hash_entry *entry, dev_t dev, ino_t ino,
                         time_t mtime, off_t size, const char *hash)
{
    entry->dev = dev;
    entry->ino = ino;
    entry->mtime = mtime;
    entry->size = size;
    strncpy(entry->hash, hash, SHA256_HEX_LEN - 1);
    entry->hash[SHA256_HEX_LEN - 1] = '\0';
    entry->access_count = ++global_access_counter;
}

// Compute SHA256 hash of file
static bool compute_sha256(const char *path, char *hash_out, struct stat *st_out)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char buffer[READ_BUFFER_SIZE];
    EVP_MD_CTX *mdctx;
    int fd;
    ssize_t bytes;
    unsigned int hash_len;
    struct stat st;

    // Open file first to avoid TOCTOU race
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;

    // Get file metadata from already-opened fd (no TOCTOU)
    if (fstat(fd, &st) < 0) {
        close(fd);
        return false;
    }

    // Return stat info for cache validation
    if (st_out)
        *st_out = st;

    // Skip non-regular files
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return false;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        close(fd);
        return false;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        close(fd);
        return false;
    }

    while ((bytes = read(fd, buffer, sizeof(buffer))) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes) != 1) {
            EVP_MD_CTX_free(mdctx);
            close(fd);
            return false;
        }
    }

    close(fd);

    if (bytes < 0) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    EVP_MD_CTX_free(mdctx);

    // Convert to hex string
    for (unsigned int i = 0; i < hash_len && (i * 2 + 2) < SHA256_HEX_LEN; i++) {
        snprintf(hash_out + (i * 2), 3, "%02x", hash[i]);
    }
    hash_out[SHA256_HEX_LEN - 1] = '\0';

    return true;
}

int filehash_init(const char *cache_file, int max_entries)
{
    // Set cache file path
    if (cache_file && strlen(cache_file) < PATH_MAX_LEN) {
        strncpy(cache_file_path, cache_file, PATH_MAX_LEN - 1);
        cache_file_path[PATH_MAX_LEN - 1] = '\0';
    }

    // Set max entries
    if (max_entries > 0)
        max_cache_entries = max_entries;

    // Initialize hash table
    memset(hash_table, 0, sizeof(hash_table));
    current_entries = 0;
    global_access_counter = 0;
    stat_hits = 0;
    stat_misses = 0;
    stat_recomputes = 0;

    // Try to load existing cache
    filehash_load();

    return 0;
}

void filehash_cleanup(void)
{
    // Save before cleanup
    filehash_save();

    pthread_mutex_lock(&cache_mutex);

    // Free all entries
    for (int i = 0; i < HASH_BUCKETS; i++) {
        struct hash_entry *entry = hash_table[i];
        while (entry) {
            struct hash_entry *next = entry->next;
            free(entry);
            entry = next;
        }
        hash_table[i] = NULL;
    }

    current_entries = 0;
    stat_hits = 0;
    stat_misses = 0;
    stat_recomputes = 0;

    pthread_mutex_unlock(&cache_mutex);
}

int filehash_save(void)
{
    FILE *fp;
    char tmp_path[PATH_MAX_LEN + 8];
    int saved = 0;

    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", cache_file_path);

    // Set restrictive umask before file creation (prevents world-readable files)
    mode_t old_umask = umask(0077);

    fp = fopen(tmp_path, "w");
    if (!fp) {
        int saved_errno = errno;
        umask(old_umask);  // Restore umask before returning
        return -saved_errno;
    }

    // Set restrictive permissions (0600) for defense in depth
    // Even though umask is 0077, explicitly set permissions to ensure correctness
    if (fchmod(fileno(fp), 0600) != 0) {
        int saved_errno = errno;
        umask(old_umask);  // Restore umask before error return
        fclose(fp);
        unlink(tmp_path);
        return -saved_errno;
    }

    // Restore original umask (don't affect other operations)
    umask(old_umask);

    // Write header
    if (fprintf(fp, "# LinMon hash cache v1\n") < 0 ||
        fprintf(fp, "# path|dev|ino|mtime|size|sha256\n") < 0) {
        int saved_errno = errno;
        fclose(fp);
        unlink(tmp_path);
        return -saved_errno;
    }

    pthread_mutex_lock(&cache_mutex);

    for (int i = 0; i < HASH_BUCKETS; i++) {
        struct hash_entry *entry = hash_table[i];
        while (entry) {
            if (fprintf(fp, "%s|%lu|%lu|%ld|%ld|%s\n",
                    entry->path,
                    (unsigned long)entry->dev,
                    (unsigned long)entry->ino,
                    (long)entry->mtime,
                    (long)entry->size,
                    entry->hash) < 0) {
                int saved_errno = errno;
                pthread_mutex_unlock(&cache_mutex);
                fclose(fp);
                unlink(tmp_path);
                return -saved_errno;
            }
            saved++;
            entry = entry->next;
        }
    }

    pthread_mutex_unlock(&cache_mutex);

    fclose(fp);

    // Atomic rename
    if (rename(tmp_path, cache_file_path) != 0) {
        int saved_errno = errno;
        unlink(tmp_path);
        return -saved_errno;
    }

    return saved;
}

int filehash_load(void)
{
    FILE *fp;
    char line[PATH_MAX_LEN + SHA256_HEX_LEN + 128];
    int loaded = 0;

    fp = fopen(cache_file_path, "r");
    if (!fp) {
        if (errno == ENOENT)
            return 0;  // No cache file yet
        return -errno;
    }

    pthread_mutex_lock(&cache_mutex);

    while (fgets(line, sizeof(line), fp)) {
        char path[PATH_MAX_LEN];
        unsigned long dev, ino;
        long mtime, size;
        char hash[SHA256_HEX_LEN];

        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n')
            continue;

        // Parse line: path|dev|ino|mtime|size|sha256
        if (sscanf(line, "%255[^|]|%lu|%lu|%ld|%ld|%64s",
                   path, &dev, &ino, &mtime, &size, hash) == 6) {
            // Add to cache
            if (cache_add(path, (dev_t)dev, (ino_t)ino,
                         (time_t)mtime, (off_t)size, hash)) {
                loaded++;
            }
        }
    }

    pthread_mutex_unlock(&cache_mutex);

    fclose(fp);
    return loaded;
}

void filehash_stats(unsigned long *hits, unsigned long *misses,
                    unsigned long *entries, unsigned long *recomputes)
{
    pthread_mutex_lock(&cache_mutex);

    if (hits) *hits = stat_hits;
    if (misses) *misses = stat_misses;
    if (entries) *entries = current_entries;
    if (recomputes) *recomputes = stat_recomputes;

    pthread_mutex_unlock(&cache_mutex);
}

bool filehash_calculate(const char *path, char *hash_out, size_t hash_size)
{
    struct stat st;
    struct hash_entry *entry;
    char computed_hash[SHA256_HEX_LEN];
    bool needs_compute = false;

    if (!path || !hash_out || hash_size < SHA256_HEX_LEN)
        return false;

    // Quick stat to get file info for cache lookup
    if (stat(path, &st) < 0)
        return false;

    // Only cache regular files
    if (!S_ISREG(st.st_mode))
        return false;

    pthread_mutex_lock(&cache_mutex);

    entry = cache_find(path);
    if (entry) {
        // Check if file has changed
        if (entry->dev == st.st_dev &&
            entry->ino == st.st_ino &&
            entry->mtime == st.st_mtime &&
            entry->size == st.st_size) {
            // Cache hit
            stat_hits++;
            snprintf(hash_out, hash_size, "%s", entry->hash);
            entry->access_count = ++global_access_counter;
            pthread_mutex_unlock(&cache_mutex);
            return true;
        } else {
            // File changed - need to recompute
            needs_compute = true;
            stat_recomputes++;
        }
    } else {
        // Cache miss
        stat_misses++;
        needs_compute = true;
    }

    pthread_mutex_unlock(&cache_mutex);

    if (needs_compute) {
        // Compute hash (outside mutex - this is slow)
        struct stat actual_st;
        if (!compute_sha256(path, computed_hash, &actual_st))
            return false;

        // Update cache
        pthread_mutex_lock(&cache_mutex);

        // Re-check for entry (might have been added by another thread)
        entry = cache_find(path);
        if (entry) {
            cache_update(entry, actual_st.st_dev, actual_st.st_ino,
                        actual_st.st_mtime, actual_st.st_size, computed_hash);
        } else {
            cache_add(path, actual_st.st_dev, actual_st.st_ino,
                     actual_st.st_mtime, actual_st.st_size, computed_hash);
        }

        pthread_mutex_unlock(&cache_mutex);

        snprintf(hash_out, hash_size, "%s", computed_hash);
    }

    return true;
}
