// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// Package cache implementation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <syslog.h>

#include "pkgcache.h"
#include "utils.h"

// Cache entry structure
struct cache_entry {
    char path[PKG_PATH_MAX];
    ino_t inode;
    time_t mtime;
    time_t cached_at;  // When this entry was cached (for TTL)
    char package[PKG_NAME_MAX];
    bool from_package;
    enum pkg_integrity_status integrity;
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

static int prepare_package_helper(bool allow_dac_override)
{
    cap_t caps;

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0)
        return -1;
    caps = cap_init();
    if (!caps)
        return -1;
    if (allow_dac_override) {
        cap_value_t cap = CAP_DAC_OVERRIDE;
        if (cap_set_flag(caps, CAP_PERMITTED, 1, &cap, CAP_SET) != 0 ||
            cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap, CAP_SET) != 0 ||
            cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_SET) != 0) {
            cap_free(caps);
            return -1;
        }
    }
    if (cap_set_proc(caps) != 0) {
        cap_free(caps);
        return -1;
    }
    cap_free(caps);

    if (allow_dac_override &&
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_DAC_OVERRIDE, 0, 0) != 0)
        return -1;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    return 0;
}

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

// Helper to execute package manager query without shell
// Uses fork() + execve() to avoid shell injection vulnerabilities
// Returns 0 on success with package name in buf, -1 on failure
static int try_package_query(const char *query_path, char *buf, size_t buflen)
{
	int pipefd[2];
	pid_t pid;
	char line[256];
	int ret = -1;
	int status;

	// Create pipe for reading command output
	if (pipe(pipefd) == -1)
		return -1;

	pid = fork();
	if (pid == -1) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if (pid == 0) {
		// Child process: execute package manager
		close(pipefd[0]);  // Close read end

		// Redirect stdout to pipe
		dup2(pipefd[1], STDOUT_FILENO);

		// Redirect stderr to /dev/null
		int devnull = open("/dev/null", O_WRONLY);
		if (devnull != -1) {
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}

		close(pipefd[1]);

		// Ownership queries only need access to the public package database.
		if (prepare_package_helper(false) != 0)
			_exit(127);

		// Execute without shell - direct execve() call
		if (detected_pkg_manager == PKG_DPKG) {
			char *args[] = {"/usr/bin/dpkg", "-S", (char *)query_path, NULL};
			execve("/usr/bin/dpkg", args, NULL);
		} else if (detected_pkg_manager == PKG_RPM) {
			char *args[] = {"/usr/bin/rpm", "-qf", (char *)query_path, NULL};
			execve("/usr/bin/rpm", args, NULL);
		}

		// execve() only returns on error
		_exit(127);
	}

	// Parent process: read output
	close(pipefd[1]);  // Close write end

	FILE *fp = fdopen(pipefd[0], "r");
	if (!fp) {
		close(pipefd[0]);
		waitpid(pid, NULL, 0);
		return -1;
	}

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

	fclose(fp);  // Closes pipefd[0] as well

	// Wait for child process to complete
	if (waitpid(pid, &status, 0) == -1)
		return -1;

	// Check if child exited successfully
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		// dpkg/rpm failed or crashed
		return -1;
	}

	return ret;
}

// Look up package for a file using package manager
// Returns package name in buf, or empty string if not from package
// Handles UsrMerge systems where /usr/bin/foo is hardlinked to /bin/foo
// but only /bin/foo is in the package database
static int query_package_manager(const char *path, char *buf, size_t buflen,
                                 char *owned_path, size_t owned_path_len)
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
	if (ret == 0) {
		snprintf(owned_path, owned_path_len, "%s", query_path);
		return 0;  // Success
	}

	// Try 2: Original path (if different from normalized)
	if (query_path != path) {
		ret = try_package_query(path, buf, buflen);
		if (ret == 0) {
			snprintf(owned_path, owned_path_len, "%s", path);
			return 0;  // Success
		}
	}

	// Try 3: Realpath fallback (resolves symlinks, handles hardlinks)
	if (realpath(path, realpath_buf) != NULL) {
		// Only try if realpath is different from both previous attempts
		if (strcmp(realpath_buf, path) != 0 &&
		    strcmp(realpath_buf, query_path) != 0) {
			ret = try_package_query(realpath_buf, buf, buflen);
			if (ret == 0) {
				snprintf(owned_path, owned_path_len, "%s", realpath_buf);
				return 0;  // Success
			}
		}
	}

	// All attempts failed
	return -1;
}

// Verify one package-owned file using the package manager's installed checksums.
// dpkg --verify emits RPM-style lines only for mismatches; rpm -Vf does the same.
static enum pkg_integrity_status verify_package_file(const char *package,
                                                       const char *owned_path)
{
    int pipefd[2], status;
    pid_t pid;
    FILE *fp;
    char line[PKG_PATH_MAX + 64];
    bool mismatch = false;

    if (!package || !*package || !owned_path || !*owned_path)
        return PKG_INTEGRITY_UNVERIFIABLE;
    if (pipe(pipefd) != 0)
        return PKG_INTEGRITY_UNVERIFIABLE;

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        return PKG_INTEGRITY_UNVERIFIABLE;
    }
    if (pid == 0) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0 ||
            dup2(pipefd[1], STDERR_FILENO) < 0)
            _exit(127);
        close(pipefd[1]);
        // During privileged startup retain only DAC_OVERRIDE so dpkg/rpm can
        // verify execute-only or root-readable files. Runtime helpers retain no
        // capabilities, preserving the daemon's minimal steady-state profile.
        if (prepare_package_helper(geteuid() == 0) != 0)
            _exit(127);
        if (detected_pkg_manager == PKG_DPKG) {
            char *args[] = {"/usr/bin/dpkg", "--verify", (char *)package, NULL};
            execve(args[0], args, NULL);
        } else if (detected_pkg_manager == PKG_RPM) {
            char *args[] = {"/usr/bin/rpm", "-Vf", (char *)owned_path, NULL};
            execve(args[0], args, NULL);
        }
        _exit(127);
    }

    close(pipefd[1]);
    fp = fdopen(pipefd[0], "r");
    if (!fp) {
        close(pipefd[0]);
        waitpid(pid, NULL, 0);
        return PKG_INTEGRITY_UNVERIFIABLE;
    }
    while (fgets(line, sizeof(line), fp)) {
        size_t line_len = strlen(line);
        size_t path_len = strlen(owned_path);
        while (line_len && (line[line_len - 1] == '\n' || line[line_len - 1] == '\r'))
            line[--line_len] = '\0';
        if (line_len >= path_len &&
            strcmp(line + line_len - path_len, owned_path) == 0)
            mismatch = true;
    }
    fclose(fp);
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status))
        return PKG_INTEGRITY_UNVERIFIABLE;
    if (mismatch)
        return PKG_INTEGRITY_MODIFIED;
    if (WEXITSTATUS(status) != 0)
        return PKG_INTEGRITY_UNVERIFIABLE;
    return PKG_INTEGRITY_VERIFIED;
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
                                      bool from_package,
                                      enum pkg_integrity_status integrity)
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
    entry->integrity = integrity;

    h = hash_path(path);
    entry->next = hash_table[h];
    hash_table[h] = entry;
    current_entries++;

    return entry;
}

// Update existing entry
static void cache_update(struct cache_entry *entry, ino_t inode,
                         time_t mtime, const char *package, bool from_package,
                         enum pkg_integrity_status integrity)
{
    entry->inode = inode;
    entry->mtime = mtime;
    entry->cached_at = time(NULL);  // Update cache timestamp
    strncpy(entry->package, package, PKG_NAME_MAX - 1);
    entry->package[PKG_NAME_MAX - 1] = '\0';
    entry->from_package = from_package;
    entry->integrity = integrity;
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

static int pkgcache_lookup_internal(const char *path, struct pkg_info *info,
                                    bool force_verify)
{
    struct stat st;
    struct cache_entry *entry;
    char package[PKG_NAME_MAX] = {0};
    char owned_path[PKG_PATH_MAX] = {0};
    enum pkg_integrity_status integrity = PKG_INTEGRITY_UNVERIFIABLE;
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
        if (force_verify || entry->inode != st.st_ino || entry->mtime != st.st_mtime ||
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
            info->integrity = entry->integrity;
            info->modified = entry->integrity == PKG_INTEGRITY_MODIFIED;
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
        ret = query_package_manager(path, package, sizeof(package),
                                    owned_path, sizeof(owned_path));
        if (ret == 0 && package[0] != '\0')
            integrity = verify_package_file(package, owned_path);

        pthread_mutex_lock(&cache_mutex);
        // Re-find after the unlocked package-manager call so concurrent cache
        // maintenance cannot leave us with a stale entry pointer.
        entry = cache_find(path);

        if (ret == 0 && package[0] != '\0') {
            // File belongs to a package
            info->from_package = true;
            strncpy(info->package, package, PKG_NAME_MAX - 1);
            info->package[PKG_NAME_MAX - 1] = '\0';

            info->integrity = integrity;
            info->modified = info->integrity == PKG_INTEGRITY_MODIFIED;
            if (entry) {
                cache_update(entry, st.st_ino, st.st_mtime, package, true,
                             info->integrity);
            } else {
                cache_add(path, st.st_ino, st.st_mtime, package, true,
                          info->integrity);
            }
        } else {
            // File not from a package
            info->from_package = false;
            info->package[0] = '\0';
            info->integrity = PKG_INTEGRITY_UNPACKAGED;
            info->modified = false;

            if (entry) {
                cache_update(entry, st.st_ino, st.st_mtime, "", false,
                             PKG_INTEGRITY_UNPACKAGED);
            } else {
                cache_add(path, st.st_ino, st.st_mtime, "", false,
                          PKG_INTEGRITY_UNPACKAGED);
            }
        }

        pthread_mutex_unlock(&cache_mutex);
    }

    return 0;
}

int pkgcache_lookup(const char *path, struct pkg_info *info)
{
    return pkgcache_lookup_internal(path, info, false);
}

int pkgcache_verify(const char *path, struct pkg_info *info)
{
    return pkgcache_lookup_internal(path, info, true);
}

int pkgcache_save(void)
{
    FILE *fp;
    char tmp_path[PKG_PATH_MAX + 8];
    int i;

    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", cache_file_path);

    // Use safe_fopen to prevent symlink attacks (O_NOFOLLOW)
    // Sets permissions atomically (0600 = rw-------)
    // Prevents information leakage of system paths
    fp = safe_fopen(tmp_path, "w", 0600);
    if (!fp) {
        int saved_errno = errno;
        if (saved_errno == ELOOP) {
            // Symlink attack detected - log security event
            syslog(LOG_WARNING | LOG_AUTH,
                   "SECURITY: Symlink attack detected on package cache: %s", tmp_path);
        }
        return -saved_errno;
    }

    // Write header
    fprintf(fp, "# LinMon package cache v3\n");
    fprintf(fp, "# path|inode|mtime|cached_at|package|from_pkg|integrity\n");

    pthread_mutex_lock(&cache_mutex);

    for (i = 0; i < HASH_BUCKETS; i++) {
        struct cache_entry *entry = hash_table[i];
        while (entry) {
            fprintf(fp, "%s|%lu|%ld|%ld|%s|%d|%d\n",
                    entry->path,
                    (unsigned long)entry->inode,
                    (long)entry->mtime,
                    (long)entry->cached_at,
                    entry->package,
                    entry->from_package ? 1 : 0, (int)entry->integrity);
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
    struct stat st;
    char line[PKG_PATH_MAX + PKG_NAME_MAX + 64];
    int loaded = 0;
    bool v3 = false;

    fp = safe_fopen_readonly(cache_file_path, &st);
    if (!fp) {
        if (errno == ENOENT)
            return 0;  // No cache file yet, that's OK
        return -errno;
    }

    if (!S_ISREG(st.st_mode)) {
        fclose(fp);
        return -EPERM;
    }

    pthread_mutex_lock(&cache_mutex);

    while (fgets(line, sizeof(line), fp)) {
        char path[PKG_PATH_MAX];
        unsigned long inode;
        long mtime, cached_at;
        char package[PKG_NAME_MAX];
        int from_pkg;

        if (strncmp(line, "# LinMon package cache v3", 25) == 0) {
            v3 = true;
            continue;
        }
        // Old cache formats lack integrity state. Ignore them so every entry is
        // revalidated rather than being treated as clean.
        if (line[0] == '#' || line[0] == '\n' || !v3)
            continue;

        int integrity;
        if (sscanf(line, "%4095[^|]|%lu|%ld|%ld|%63[^|]|%d|%d",
                   path, &inode, &mtime, &cached_at, package, &from_pkg,
                   &integrity) == 7 &&
            integrity >= PKG_INTEGRITY_UNVERIFIABLE &&
            integrity <= PKG_INTEGRITY_UNPACKAGED) {
            struct cache_entry *entry = cache_add(
                path, (ino_t)inode, (time_t)mtime, package, from_pkg != 0,
                (enum pkg_integrity_status)integrity);
            if (entry) {
                entry->cached_at = (time_t)cached_at;
                loaded++;
            }
        } else if (sscanf(line, "%4095[^|]|%lu|%ld|%ld||%d|%d",
                          path, &inode, &mtime, &cached_at, &from_pkg,
                          &integrity) == 6 &&
                   integrity >= PKG_INTEGRITY_UNVERIFIABLE &&
                   integrity <= PKG_INTEGRITY_UNPACKAGED) {
            struct cache_entry *entry = cache_add(
                path, (ino_t)inode, (time_t)mtime, "", from_pkg != 0,
                (enum pkg_integrity_status)integrity);
            if (entry) {
                entry->cached_at = (time_t)cached_at;
                loaded++;
            }
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
