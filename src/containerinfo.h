// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// Container identification via cgroup parsing

#ifndef __CONTAINERINFO_H
#define __CONTAINERINFO_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

// Maximum length for container ID (64 hex chars for Docker/Podman)
#define CONTAINER_ID_LEN 65

// Initial namespace inode numbers (host/init namespaces)
#define PROC_PID_INIT_INO  4026531836  // Initial PID namespace
#define PROC_MNT_INIT_INO  4026531840  // Initial mount namespace
#define PROC_NET_INIT_INO  4026531841  // Initial network namespace

// Container runtime types
enum container_runtime {
    RUNTIME_NONE = 0,
    RUNTIME_DOCKER,
    RUNTIME_PODMAN,
    RUNTIME_CONTAINERD,
    RUNTIME_LXC,
    RUNTIME_SYSTEMD_NSPAWN,
    RUNTIME_KUBERNETES,  // Pod (contains multiple containers)
    RUNTIME_UNKNOWN
};

// Container information extracted from /proc/<pid>/cgroup
struct container_info {
    enum container_runtime runtime;
    char id[CONTAINER_ID_LEN];       // Container ID (hex string)
    char pod_id[CONTAINER_ID_LEN];   // Kubernetes pod ID (if applicable)
};

// Parse /proc/<pid>/cgroup to extract container information
// Returns true if process is in a container, false if on host
// info struct is populated with container details
bool containerinfo_get(pid_t pid, struct container_info *info);

// Helper: check if namespace inodes indicate container
static inline bool containerinfo_is_in_container(uint32_t pid_ns, uint32_t mnt_ns, uint32_t net_ns)
{
    // Sanity check: namespace inodes should be non-zero (detect corrupted/invalid data)
    if (pid_ns == 0 || mnt_ns == 0 || net_ns == 0)
        return false;

    // If any namespace differs from init namespace, process is in container
    // Note: some namespaces may match host even in containers (e.g., network in host mode)
    return (pid_ns != PROC_PID_INIT_INO ||  // 4026531836
            mnt_ns != PROC_MNT_INIT_INO ||  // 4026531840
            net_ns != PROC_NET_INIT_INO);   // 4026531841
}

#endif /* __CONTAINERINFO_H */
