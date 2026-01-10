// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// User database - UID to username resolution with caching

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <pwd.h>
#include <pthread.h>

#include "userdb.h"

#define CACHE_SIZE 256

struct cache_entry {
    uid_t uid;
    char username[USERNAME_MAX];
    bool valid;
};

static struct cache_entry cache[CACHE_SIZE];
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

void userdb_init(void)
{
    memset(cache, 0, sizeof(cache));
}

void userdb_cleanup(void)
{
    // Nothing to cleanup - static allocation
}

static int cache_hash(uid_t uid)
{
    // Better hash function to reduce collisions
    // Uses multiplication and bit mixing for better distribution
    unsigned int h = uid;
    h = ((h >> 16) ^ h) * 0x45d9f3b;
    h = ((h >> 16) ^ h) * 0x45d9f3b;
    h = (h >> 16) ^ h;
    return h % CACHE_SIZE;
}

void userdb_resolve(uid_t uid, char *buf, size_t buf_size)
{
    struct passwd pwd;
    struct passwd *result;
    char pwbuf[4096];  // Larger buffer to handle systems with many groups
    int idx;
    bool cache_hit;
    int ret;

    if (!buf || buf_size == 0)
        return;

    pthread_mutex_lock(&cache_mutex);

    // Check cache
    idx = cache_hash(uid);
    cache_hit = (cache[idx].valid && cache[idx].uid == uid);
    if (cache_hit) {
        snprintf(buf, buf_size, "%s", cache[idx].username);
        pthread_mutex_unlock(&cache_mutex);
        return;
    }

    // Cache miss - release mutex while doing expensive getpwuid_r call
    pthread_mutex_unlock(&cache_mutex);

    // Look up user (this is slow - OK to do without lock)
    ret = getpwuid_r(uid, &pwd, pwbuf, sizeof(pwbuf), &result);
    if (ret == 0 && result) {
        // Success - update cache and return
        pthread_mutex_lock(&cache_mutex);
        // Re-check cache in case another thread updated it while we were unlocked
        if (cache[idx].valid && cache[idx].uid == uid) {
            // Another thread already cached this - use their result
            snprintf(buf, buf_size, "%s", cache[idx].username);
        } else {
            // We're first - cache our result
            cache[idx].uid = uid;
            cache[idx].valid = true;
            snprintf(cache[idx].username, USERNAME_MAX, "%s", pwd.pw_name);
            snprintf(buf, buf_size, "%s", pwd.pw_name);
        }
        pthread_mutex_unlock(&cache_mutex);
    } else {
        // User not found or error - use UID_XXXX format and cache negative result
        // Log warning if buffer was too small (ERANGE)
        if (ret == ERANGE) {
            fprintf(stderr, "Warning: getpwuid_r buffer too small for UID %u\n", uid);
        }

        snprintf(buf, buf_size, "UID_%u", uid);

        pthread_mutex_lock(&cache_mutex);
        // Re-check cache in case another thread updated it
        if (!(cache[idx].valid && cache[idx].uid == uid)) {
            cache[idx].uid = uid;
            cache[idx].valid = true;
            snprintf(cache[idx].username, USERNAME_MAX, "UID_%u", uid);
        }
        pthread_mutex_unlock(&cache_mutex);
    }
}
