// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// Container identification via cgroup parsing

#include "containerinfo.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

// Extract container ID from cgroup path
// Supports Docker, Podman, containerd, Kubernetes patterns
static bool extract_container_id(const char *cgroup_path, struct container_info *info)
{
    const char *p;

    // Docker pattern: /docker-<container-id> or /docker/<container-id>
    // Example: /system.slice/docker-a1b2c3d4e5f6.scope
    if ((p = strstr(cgroup_path, "/docker-")) != NULL) {
        info->runtime = RUNTIME_DOCKER;
        p += 8;  // Skip "/docker-"
    } else if ((p = strstr(cgroup_path, "/docker/")) != NULL) {
        info->runtime = RUNTIME_DOCKER;
        p += 8;  // Skip "/docker/"
    }

    if (info->runtime == RUNTIME_DOCKER) {
        // Extract hex ID (up to 64 chars)
        int i = 0;
        while (i < CONTAINER_ID_LEN - 1 && *p &&
               ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) {
            info->id[i++] = *p++;
        }
        info->id[i] = '\0';

        // Validate minimum ID length (Docker IDs are 64 hex chars, but accept >= 12)
        if (i >= 12) {
            return true;
        }
        // Too short, reset and try other patterns
        info->runtime = RUNTIME_NONE;
        info->id[0] = '\0';
    }

    // Podman pattern: /libpod-<container-id>.scope
    if ((p = strstr(cgroup_path, "/libpod-")) != NULL) {
        info->runtime = RUNTIME_PODMAN;
        p += 8;  // Skip "/libpod-"

        int i = 0;
        while (i < CONTAINER_ID_LEN - 1 && *p &&
               ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) {
            info->id[i++] = *p++;
        }
        info->id[i] = '\0';
        return (i >= 12);  // Validate minimum ID length
    }

    // Kubernetes pattern: /kubepods/pod<uuid>/<container-id>
    // or /kubepods.slice/kubepods-<qos>.slice/kubepods-<qos>-pod<uuid>.slice/cri-containerd-<id>.scope
    if ((p = strstr(cgroup_path, "/kubepods")) != NULL) {
        info->runtime = RUNTIME_KUBERNETES;

        // Extract pod ID (UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx or xxxxxxxx_xxxx_xxxx_xxxx_xxxxxxxxxxxx)
        const char *pod = strstr(p, "/pod");
        if (!pod) pod = strstr(p, "-pod");
        if (pod) {
            pod += 4;  // Skip "/pod" or "-pod"
            int i = 0;
            while (i < CONTAINER_ID_LEN - 1 && *pod &&
                   ((*pod >= '0' && *pod <= '9') || (*pod >= 'a' && *pod <= 'f') ||
                    *pod == '-' || *pod == '_')) {
                info->pod_id[i++] = *pod++;
            }
            info->pod_id[i] = '\0';
        }

        // Extract container ID (may be cri-containerd-<id>, crio-<id>, or docker-<id>)
        const char *cri = strstr(cgroup_path, "cri-containerd-");
        if (!cri) cri = strstr(cgroup_path, "crio-");
        if (!cri) cri = strstr(cgroup_path, "docker-");

        if (cri) {
            // Skip to ID part
            p = strchr(cri, '-');
            if (p) {
                p = strchr(p + 1, '-');  // Skip "cri-" or "crio-"
                if (p) p++;
            }
            if (!p) p = cri;

            int i = 0;
            while (i < CONTAINER_ID_LEN - 1 && *p &&
                   ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) {
                info->id[i++] = *p++;
            }
            info->id[i] = '\0';
            return (i > 0);
        }

        return (info->pod_id[0] != '\0');  // At least have pod ID
    }

    // containerd pattern (non-k8s): /system.slice/containerd.service/...
    if (strstr(cgroup_path, "/containerd") != NULL) {
        info->runtime = RUNTIME_CONTAINERD;
        // Try to extract ID from path
        const char *last_slash = strrchr(cgroup_path, '/');
        if (last_slash) {
            p = last_slash + 1;
            int i = 0;
            while (i < CONTAINER_ID_LEN - 1 && *p &&
                   ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) {
                info->id[i++] = *p++;
            }
            info->id[i] = '\0';
            if (i >= 12) {
                return true;  // Valid ID found
            }
        }
        // No valid ID, but still detected as containerd
        return true;
    }

    // LXC pattern: /lxc/<container-name>
    if ((p = strstr(cgroup_path, "/lxc/")) != NULL) {
        info->runtime = RUNTIME_LXC;
        p += 5;  // Skip "/lxc/"

        // LXC uses names, not IDs
        int i = 0;
        while (i < CONTAINER_ID_LEN - 1 && *p && *p != '/' && *p != '.') {
            info->id[i++] = *p++;
        }
        info->id[i] = '\0';
        return (i > 0);
    }

    // systemd-nspawn pattern: /machine.slice/machine-<name>.scope
    if ((p = strstr(cgroup_path, "/machine-")) != NULL) {
        info->runtime = RUNTIME_SYSTEMD_NSPAWN;
        p += 9;  // Skip "/machine-"

        int i = 0;
        while (i < CONTAINER_ID_LEN - 1 && *p && *p != '.') {
            info->id[i++] = *p++;
        }
        info->id[i] = '\0';
        return (i > 0);
    }

    return false;
}

// Parse /proc/<pid>/cgroup to extract container information
bool containerinfo_get(pid_t pid, struct container_info *info)
{
    char path[64];
    FILE *f;
    char line[PATH_MAX];  // Use PATH_MAX for cgroup paths (can be long in Kubernetes)
    bool found = false;

    // Initialize info
    info->runtime = RUNTIME_NONE;
    info->id[0] = '\0';
    info->pod_id[0] = '\0';

    // Open /proc/<pid>/cgroup
    snprintf(path, sizeof(path), "/proc/%d/cgroup", (int)pid);
    f = fopen(path, "r");
    if (!f) {
        return false;  // Process may have exited or /proc not accessible
    }

    // Parse cgroup file
    // Format: <hierarchy-id>:<controller-list>:<cgroup-path>
    // Example: 0::/system.slice/docker-a1b2c3d4e5f6.scope
    while (fgets(line, sizeof(line), f)) {
        // Skip to cgroup path (after second ':')
        char *cgroup_path = strchr(line, ':');
        if (!cgroup_path) continue;
        cgroup_path = strchr(cgroup_path + 1, ':');
        if (!cgroup_path) continue;
        cgroup_path++;  // Skip second ':'

        // Remove trailing newline
        size_t len = strlen(cgroup_path);
        if (len > 0 && cgroup_path[len - 1] == '\n') {
            cgroup_path[len - 1] = '\0';
        }

        // Try to extract container ID
        if (extract_container_id(cgroup_path, info)) {
            found = true;
            break;
        }
    }

    fclose(f);
    return found;
}
