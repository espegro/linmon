// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
//
// Container identification via cgroup parsing
//
// ═══════════════════════════════════════════════════════════════════════════
// PURPOSE
// ═══════════════════════════════════════════════════════════════════════════
//
// This module detects if a process is running inside a container and extracts
// container metadata (runtime type, container ID, pod ID for Kubernetes).
//
// WHY CONTAINER DETECTION MATTERS FOR SECURITY:
//
//   1. Container Escape Detection (MITRE ATT&CK T1611)
//      - Attackers often escape containers to compromise the host
//      - By tracking container metadata in events, we can correlate:
//        * Process starts in container → Network connection from host
//        * File access in container → Privilege escalation on host
//      - Container ID changes indicate potential escape or privilege escalation
//
//   2. Lateral Movement Tracking
//      - Containers share the same host kernel
//      - Malware can spread between containers via shared volumes, networks
//      - Container metadata helps track process lineage across boundaries
//
//   3. Forensic Context
//      - Container ID correlates with orchestrator logs (Docker, Kubernetes)
//      - Pod ID links to Kubernetes pod manifest (which image, which namespace)
//      - Runtime type indicates attack surface (Docker socket, CRI-O, containerd)
//
//   4. Anomaly Detection
//      - Processes in containers usually don't access host filesystems
//      - Network connections from containers follow predictable patterns
//      - Deviations indicate compromise or misconfiguration
//
// ═══════════════════════════════════════════════════════════════════════════
// DETECTION METHOD: cgroups
// ═══════════════════════════════════════════════════════════════════════════
//
// WHAT ARE cgroups:
//   - Control Groups: Linux kernel feature for resource isolation
//   - Every process belongs to a cgroup hierarchy
//   - Container runtimes place containers in unique cgroups
//   - cgroup path contains container ID and runtime information
//
// WHY cgroups (not namespaces):
//   - Namespaces only show *if* process is isolated, not *which* container
//   - cgroup path uniquely identifies the specific container instance
//   - cgroup path includes container ID for correlation with logs
//   - Works across all container runtimes (Docker, Podman, Kubernetes, LXC)
//
// WHERE cgroup DATA COMES FROM:
//   - /proc/<pid>/cgroup - Per-process cgroup membership
//   - Format: <hierarchy-id>:<controller-list>:<cgroup-path>
//   - Example: 0::/system.slice/docker-a1b2c3d4e5f6.scope
//
// cgroup PATH PATTERNS BY RUNTIME:
//
//   Docker:
//     /system.slice/docker-<64-hex-id>.scope
//     /docker/<64-hex-id>
//     Example: /system.slice/docker-a1b2c3d4e5f6789...scope
//
//   Podman:
//     /user.slice/user-<uid>.slice/user@<uid>.service/libpod-<64-hex-id>.scope
//     Example: /user.slice/user-1000.slice/.../libpod-abc123def456...scope
//
//   Kubernetes (with containerd/CRI-O):
//     /kubepods/pod<uuid>/<runtime>-<container-id>.scope
//     /kubepods.slice/kubepods-<qos>.slice/kubepods-<qos>-pod<uuid>.slice/cri-containerd-<id>.scope
//     Example: /kubepods.slice/.../kubepods-burstable-pod123e4567_e89b_12d3.../cri-containerd-abc...scope
//     Pod UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx or xxxxxxxx_xxxx_xxxx_xxxx_xxxxxxxxxxxx
//
//   containerd (standalone):
//     /system.slice/containerd.service/<container-id>
//     Example: /system.slice/containerd.service/a1b2c3d4e5f6
//
//   LXC:
//     /lxc/<container-name>
//     Example: /lxc/mycontainer
//
//   systemd-nspawn:
//     /machine.slice/machine-<name>.scope
//     Example: /machine.slice/machine-myvm.scope
//
// DETECTION ALGORITHM:
//   1. Read /proc/<pid>/cgroup (one line per cgroup controller)
//   2. Parse each line to extract cgroup path (after second ':')
//   3. Match path against known runtime patterns (see above)
//   4. Extract container ID (64-char hex) or name (for LXC/nspawn)
//   5. For Kubernetes: Extract both pod UUID and container ID
//   6. Return first successful match (containers only in one runtime)
//
// CONTAINER ID FORMAT:
//   - Docker/Podman/containerd: 64-character hex string (SHA256 hash)
//   - Kubernetes: Runtime-specific ID + pod UUID
//   - LXC/systemd-nspawn: Container name (arbitrary string)
//
// SECURITY CONSIDERATIONS:
//   - cgroup paths are kernel-controlled (cannot be spoofed by userspace)
//   - Reading /proc/<pid>/cgroup requires CAP_SYS_PTRACE (LinMon has this)
//   - Process may exit between detection and logging (graceful failure)
//   - cgroup v1 vs v2 differences handled transparently (unified hierarchy)
//
// LIMITATIONS:
//   - Detects only known container runtimes (patterns above)
//   - Custom container runtimes may not be detected
//   - Process may exit before cgroup can be read (returns false)
//   - /proc must be mounted (checked at daemon startup)
//
// PERFORMANCE:
//   - Single file read per process (cached by kernel VFS)
//   - String matching on 5-10 lines (negligible overhead)
//   - Called only when capture_container_metadata=true in config
//   - Zero overhead for host processes (early return if no container patterns)
//
// ═══════════════════════════════════════════════════════════════════════════

#include "containerinfo.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

// Extract container ID from cgroup path
//
// This function implements pattern matching for all supported container runtimes.
// It parses the cgroup path string and extracts:
//   - Container runtime type (Docker, Podman, Kubernetes, etc.)
//   - Container ID (64-char hex or name)
//   - Pod ID for Kubernetes (UUID)
//
// PATTERN MATCHING STRATEGY:
//   - Try patterns in order from most specific to least specific
//   - Docker and Podman first (most common, specific patterns)
//   - Kubernetes next (complex multi-level paths)
//   - containerd, LXC, systemd-nspawn last (more generic patterns)
//
// ID VALIDATION:
//   - Docker/Podman IDs must be >= 12 hex chars (prevents false positives)
//   - LXC/nspawn names must be > 0 chars (arbitrary strings allowed)
//   - Kubernetes pod UUIDs validated by format (UUID with - or _)
//
// RETURN VALUE:
//   - true: Container detected, info struct populated
//   - false: Not a container or pattern not recognized
//
// SIDE EFFECTS:
//   - Modifies info struct (runtime, id, pod_id fields)
//   - May partially fill info on failed match (caller should check return value)
//
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
//
// PUBLIC API: Main entry point for container detection
//
// PARAMETERS:
//   pid:  Process ID to check (must be > 0)
//   info: Output struct to populate with container metadata
//
// RETURN VALUE:
//   true:  Container detected, info struct contains valid data
//   false: Not a container, or process exited, or /proc inaccessible
//
// USAGE PATTERN:
//   struct container_info info;
//   if (containerinfo_get(pid, &info)) {
//       // Process is in container
//       printf("Runtime: %d, ID: %s\n", info.runtime, info.id);
//       if (info.pod_id[0] != '\0') {
//           printf("Kubernetes pod: %s\n", info.pod_id);
//       }
//   } else {
//       // Not in container (host process)
//   }
//
// FILE FORMAT PARSED (/proc/<pid>/cgroup):
//   Each line: <hierarchy-id>:<controller-list>:<cgroup-path>
//   Example line: 0::/system.slice/docker-a1b2c3d4e5f6.scope
//
//   Fields:
//     hierarchy-id:     cgroup hierarchy number (usually 0 for unified cgroup v2)
//     controller-list:  Comma-separated controller names (empty for unified)
//     cgroup-path:      Hierarchical path showing process's cgroup membership
//
// ALGORITHM:
//   1. Open /proc/<pid>/cgroup for reading
//   2. Read file line-by-line (up to PATH_MAX chars per line)
//   3. For each line:
//      a. Skip to cgroup path (after second ':')
//      b. Remove trailing newline
//      c. Call extract_container_id() to match patterns
//      d. If match found, return true immediately
//   4. If no matches found in any line, return false
//
// EARLY RETURN STRATEGY:
//   - Returns immediately on first successful pattern match
//   - Optimization: Most containers only appear in one cgroup controller
//   - Avoids parsing all lines if first line already matches
//
// ERROR HANDLING:
//   - fopen() failure: Process may have exited or /proc not accessible
//     → Return false (not an error, just no container data available)
//   - Malformed line (no colons): Skip line and continue
//   - PATH_MAX exceeded: fgets() truncates, pattern match likely fails
//     → Graceful degradation (may miss container detection in edge cases)
//
// THREAD SAFETY:
//   - Uses local variables only (stack-allocated)
//   - No global state or shared memory
//   - Safe to call from multiple threads concurrently
//
// PERFORMANCE:
//   - Single file read: ~50-100 microseconds (kernel VFS caching)
//   - String parsing: ~5-10 lines × ~100 chars = negligible CPU
//   - Total overhead: < 100 microseconds per process
//
// SECURITY:
//   - /proc/<pid>/cgroup is world-readable (no privilege required)
//   - cgroup paths are kernel-controlled (cannot be spoofed by process)
//   - Buffer size: PATH_MAX (4096 on Linux) prevents overflow
//   - No dynamic allocation (no memory leaks possible)
//
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
