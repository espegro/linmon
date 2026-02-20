// SPDX-License-Identifier: GPL-2.0-or-later
// Safe file operations with symlink protection

#include "utils.h"
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

FILE *safe_fopen(const char *path, const char *mode, mode_t perms) {
    int flags = O_NOFOLLOW | O_CLOEXEC;

    // Parse mode string (supports "r", "w", "a" - checks first character only)
    if (mode[0] == 'a')
        flags |= O_WRONLY | O_APPEND | O_CREAT;
    else if (mode[0] == 'w')
        flags |= O_WRONLY | O_TRUNC | O_CREAT;
    else if (mode[0] == 'r')
        flags |= O_RDONLY;
    else {
        errno = EINVAL;
        return NULL;
    }

    int fd = open(path, flags, perms);
    if (fd == -1) return NULL;  // errno preserved (ELOOP if symlink)

    FILE *fp = fdopen(fd, mode);
    if (!fp) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
    }
    return fp;
}
