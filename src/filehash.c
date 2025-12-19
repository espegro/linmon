// SPDX-License-Identifier: GPL-2.0
// File hashing - SHA256 calculation with caching

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/sha.h>  // For SHA256_DIGEST_LENGTH constant

#include "filehash.h"

#define CACHE_SIZE 1000
#define READ_BUFFER_SIZE 8192

struct cache_entry {
    dev_t dev;
    ino_t ino;
    time_t mtime;
    off_t size;
    char hash[SHA256_HEX_LEN];
    bool valid;
    unsigned long access_count;  // For LRU
};

static struct cache_entry cache[CACHE_SIZE];
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned long global_access_counter = 0;

void filehash_init(void)
{
    memset(cache, 0, sizeof(cache));
}

void filehash_cleanup(void)
{
    // Nothing to cleanup - static allocation
}

static int cache_hash(dev_t dev, ino_t ino)
{
    return (dev ^ ino) % CACHE_SIZE;
}

// Find LRU entry in cache for eviction
static int find_lru_entry(void)
{
    int lru_idx = 0;
    unsigned long min_access = cache[0].access_count;

    for (int i = 1; i < CACHE_SIZE; i++) {
        if (!cache[i].valid) {
            return i;  // Empty slot
        }
        if (cache[i].access_count < min_access) {
            min_access = cache[i].access_count;
            lru_idx = i;
        }
    }
    return lru_idx;
}

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

    // Convert to hex string (hash_len should be 32 for SHA256)
    // Ensure we don't overflow hash_out buffer
    if (hash_len > 32) {
        return false;  // Unexpected hash length
    }

    for (unsigned int i = 0; i < hash_len && (i * 2 + 2) < SHA256_HEX_LEN; i++) {
        snprintf(hash_out + (i * 2), 3, "%02x", hash[i]);
    }
    hash_out[SHA256_HEX_LEN - 1] = '\0';

    return true;
}

bool filehash_calculate(const char *path, char *hash_out, size_t hash_size)
{
    struct stat st;
    int idx;
    bool cache_hit = false;

    if (!path || !hash_out || hash_size < SHA256_HEX_LEN)
        return false;

    // Quick stat to get dev/ino for cache lookup (not used for security)
    // The real stat happens inside compute_sha256() after open()
    if (stat(path, &st) < 0)
        return false;

    pthread_mutex_lock(&cache_mutex);
    global_access_counter++;

    // Check cache
    idx = cache_hash(st.st_dev, st.st_ino);
    if (cache[idx].valid &&
        cache[idx].dev == st.st_dev &&
        cache[idx].ino == st.st_ino &&
        cache[idx].mtime == st.st_mtime &&
        cache[idx].size == st.st_size) {
        // Cache hit
        snprintf(hash_out, hash_size, "%s", cache[idx].hash);
        cache[idx].access_count = global_access_counter;
        cache_hit = true;
    }

    pthread_mutex_unlock(&cache_mutex);

    if (cache_hit)
        return true;

    // Cache miss - compute hash
    // compute_sha256 will do fstat() after open() to avoid TOCTOU
    struct stat actual_st;
    if (!compute_sha256(path, hash_out, &actual_st))
        return false;

    // Update cache with actual file stats from fstat()
    pthread_mutex_lock(&cache_mutex);

    // If slot is occupied by different file, find LRU entry
    if (cache[idx].valid &&
        (cache[idx].dev != actual_st.st_dev || cache[idx].ino != actual_st.st_ino)) {
        idx = find_lru_entry();
    }

    cache[idx].dev = actual_st.st_dev;
    cache[idx].ino = actual_st.st_ino;
    cache[idx].mtime = actual_st.st_mtime;
    cache[idx].size = actual_st.st_size;
    cache[idx].valid = true;
    cache[idx].access_count = global_access_counter;
    snprintf(cache[idx].hash, SHA256_HEX_LEN, "%s", hash_out);

    pthread_mutex_unlock(&cache_mutex);

    return true;
}
