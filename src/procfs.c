// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// Process filesystem utilities

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "procfs.h"

bool procfs_read_cmdline(pid_t pid, char *buf, size_t max_len)
{
    char path[64];
    int fd;
    ssize_t bytes_read;
    ssize_t i;

    if (!buf || max_len == 0)
        return false;

    // Initialize buffer
    buf[0] = '\0';

    // Build path to /proc/<pid>/cmdline
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    // Open cmdline file
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        // Process may have exited already
        return false;
    }

    // Read cmdline (null-separated arguments)
    bytes_read = read(fd, buf, max_len - 1);
    close(fd);

    if (bytes_read <= 0) {
        buf[0] = '\0';
        return false;
    }

    // Null-terminate
    buf[bytes_read] = '\0';

    // Replace null bytes with spaces (cmdline args are null-separated)
    // Only process if we have more than 1 byte
    for (i = 0; i < bytes_read - 1; i++) {
        if (buf[i] == '\0')
            buf[i] = ' ';
    }

    // Trim trailing spaces/nulls
    while (bytes_read > 0 && (buf[bytes_read - 1] == ' ' || buf[bytes_read - 1] == '\0')) {
        buf[bytes_read - 1] = '\0';
        bytes_read--;
    }

    return true;
}

bool procfs_read_sudo_info(pid_t pid, uid_t *sudo_uid, char *sudo_user, size_t sudo_user_len)
{
    char path[64];
    char buf[4096];
    int fd;
    ssize_t bytes_read;
    bool found_uid = false;

    if (sudo_user && sudo_user_len > 0)
        sudo_user[0] = '\0';

    snprintf(path, sizeof(path), "/proc/%d/environ", pid);

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;

    bytes_read = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (bytes_read <= 0)
        return false;

    buf[bytes_read] = '\0';

    // Environment variables are null-separated
    char *ptr = buf;
    char *end = buf + bytes_read;

    while (ptr < end) {
        if (strncmp(ptr, "SUDO_UID=", 9) == 0 && sudo_uid) {
            *sudo_uid = (uid_t)strtoul(ptr + 9, NULL, 10);
            found_uid = true;
        } else if (strncmp(ptr, "SUDO_USER=", 10) == 0 && sudo_user && sudo_user_len > 0) {
            strncpy(sudo_user, ptr + 10, sudo_user_len - 1);
            sudo_user[sudo_user_len - 1] = '\0';
        }
        ptr += strlen(ptr) + 1;
    }

    return found_uid;
}
