// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// LinMon - Consolidated eBPF program for all monitoring

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

// Configuration map - shared with userspace
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct bpf_config);
} config_map SEC(".maps");

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); // 1MB ring buffer (increased from 256KB)
} events SEC(".maps");

// Rate limiting state per UID
struct rate_limit_state {
    __u64 last_refill;  // Last time tokens were refilled
    __u32 tokens;       // Available tokens
};

// Rate limiting map - tracks token bucket per UID
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // UID
    __type(value, struct rate_limit_state);
} rate_limit_map SEC(".maps");

// Network CIDR filtering map - stores up to 16 CIDR blocks to ignore
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);  // Reduced from 32 for RHEL 9 BPF verifier compatibility
    __type(key, __u32);       // Index (0-15)
    __type(value, struct network_cidr);
} ignore_networks_map SEC(".maps");

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// Token bucket rate limiting:
// - Allow burst of up to 50 events (increased from 20)
// - Refill at 200 events/second (1 token per 5ms, increased from 100/sec)
// - This allows normal activity spikes while preventing flooding
// - UID 0 (root) is shared by many system processes, needs higher limits
#define RATE_LIMIT_MAX_TOKENS 50
#define RATE_LIMIT_REFILL_INTERVAL_NS 5000000ULL  // 5ms = 200 events/sec

static __always_inline bool should_rate_limit(__u32 uid)
{
    __u64 now = bpf_ktime_get_ns();
    struct rate_limit_state *state;
    struct rate_limit_state new_state;
    __u64 elapsed;
    __u32 new_tokens;

    state = bpf_map_lookup_elem(&rate_limit_map, &uid);
    if (!state) {
        // First event from this UID - initialize with full bucket
        new_state.last_refill = now;
        new_state.tokens = RATE_LIMIT_MAX_TOKENS - 1;  // Consume one token for this event
        bpf_map_update_elem(&rate_limit_map, &uid, &new_state, BPF_ANY);
        return false;
    }

    // Calculate how many tokens to add based on elapsed time
    elapsed = now - state->last_refill;
    new_tokens = elapsed / RATE_LIMIT_REFILL_INTERVAL_NS;

    // Refill tokens if enough time has passed
    if (new_tokens > 0) {
        state->tokens += new_tokens;
        if (state->tokens > RATE_LIMIT_MAX_TOKENS)
            state->tokens = RATE_LIMIT_MAX_TOKENS;
        state->last_refill = now;
    }

    // Check if we have tokens available
    if (state->tokens == 0) {
        return true;  // Rate limited - no tokens available
    }

    // Consume one token
    state->tokens--;
    bpf_map_update_elem(&rate_limit_map, &uid, state, BPF_ANY);
    return false;
}

// Helper to check if UID should be monitored
static __always_inline bool should_monitor_uid(__u32 uid)
{
    __u32 key = 0;
    struct bpf_config *cfg;

    cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return true;  // If no config, monitor everything

    // Check min_uid
    if (uid < cfg->min_uid)
        return false;

    // Check max_uid (0 = no limit)
    if (cfg->max_uid > 0 && uid > cfg->max_uid)
        return false;

    return true;
}

// Helper to check if process should be monitored based on TTY requirement
static __always_inline bool should_monitor_session(struct task_struct *task)
{
    __u32 key = 0;
    struct bpf_config *cfg;

    cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return true;  // If no config, monitor everything

    // If require_tty is disabled, monitor all sessions
    if (!cfg->require_tty)
        return true;

    // require_tty is enabled - check for controlling TTY
    struct signal_struct *signal;
    struct tty_struct *tty;

    signal = BPF_CORE_READ(task, signal);
    if (!signal)
        return false;

    tty = BPF_CORE_READ(signal, tty);
    if (!tty)
        return false;

    return true;
}

// Helper to check if this is a thread (not main process)
static __always_inline bool is_thread(void)
{
    __u32 key = 0;
    struct bpf_config *cfg;
    __u64 pid_tgid;
    __u32 pid, tgid;

    cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg || !cfg->ignore_threads)
        return false;  // Thread filtering disabled

    // Get PID and TGID
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid & 0xFFFFFFFF;       // Lower 32 bits = TID (thread ID)
    tgid = pid_tgid >> 32;             // Upper 32 bits = TGID (process ID)

    // If pid != tgid, this is a thread
    return (pid != tgid);
}

// Helper to check if IPv4 address should be ignored (CIDR filtering)
static __always_inline bool should_ignore_network(__u32 addr)
{
    struct network_cidr *cidr;

    // Manually unrolled loop for RHEL 9 / kernel 5.14 compatibility
    // The BPF verifier in older kernels doesn't support bounded loops well
    // Reduced from 32 to 16 max CIDR blocks for code size
    #define CHECK_CIDR(idx) \
        cidr = bpf_map_lookup_elem(&ignore_networks_map, &(int){idx}); \
        if (cidr && ((addr & cidr->mask) == cidr->addr)) return true;

    CHECK_CIDR(0);  CHECK_CIDR(1);  CHECK_CIDR(2);  CHECK_CIDR(3);
    CHECK_CIDR(4);  CHECK_CIDR(5);  CHECK_CIDR(6);  CHECK_CIDR(7);
    CHECK_CIDR(8);  CHECK_CIDR(9);  CHECK_CIDR(10); CHECK_CIDR(11);
    CHECK_CIDR(12); CHECK_CIDR(13); CHECK_CIDR(14); CHECK_CIDR(15);

    #undef CHECK_CIDR
    return false;  // Address not in any ignored range
}

// Helper to fill session information (sid, pgid, tty)
static __always_inline void fill_session_info(struct process_event *event,
                                               struct task_struct *task)
{
    struct signal_struct *signal;
    struct tty_struct *tty;
    struct pid *session_pid;
    struct pid *pgrp_pid;

    // Initialize to safe defaults
    event->sid = 0;
    event->pgid = 0;
    event->tty[0] = '\0';

    signal = BPF_CORE_READ(task, signal);
    if (!signal)
        return;

    // Read session ID (pid namespace aware)
    session_pid = BPF_CORE_READ(signal, pids[PIDTYPE_SID]);
    if (session_pid) {
        // Get the numeric session ID from the pid struct
        // For simplicity, use the task's session leader's pid
        event->sid = BPF_CORE_READ(task, group_leader, tgid);
    }

    // Read process group ID
    pgrp_pid = BPF_CORE_READ(signal, pids[PIDTYPE_PGID]);
    if (pgrp_pid) {
        // Use tgid of group leader as pgid approximation
        event->pgid = BPF_CORE_READ(task, tgid);
    }

    // Read TTY name if available
    tty = BPF_CORE_READ(signal, tty);
    if (tty) {
        // Read TTY name - tty->name is a char array
        bpf_probe_read_kernel_str(&event->tty, sizeof(event->tty),
                                   &tty->name);
    }
}

// Generic macro to fill process context (ppid, sid, pgid, tty) for any event type
// Works with file_event, network_event, privilege_event, security_event
#define FILL_PROCESS_CONTEXT(event, task) \
    do { \
        struct task_struct *parent; \
        struct signal_struct *signal; \
        struct tty_struct *tty; \
        struct pid *session_pid; \
        struct pid *pgrp_pid; \
        \
        /* Fill ppid */ \
        parent = BPF_CORE_READ(task, real_parent); \
        if (parent) { \
            (event)->ppid = BPF_CORE_READ(parent, tgid); \
        } else { \
            (event)->ppid = 0; \
        } \
        \
        /* Initialize session info to safe defaults */ \
        (event)->sid = 0; \
        (event)->pgid = 0; \
        (event)->tty[0] = '\0'; \
        \
        signal = BPF_CORE_READ(task, signal); \
        if (!signal) \
            break; \
        \
        /* Read session ID (pid namespace aware) */ \
        session_pid = BPF_CORE_READ(signal, pids[PIDTYPE_SID]); \
        if (session_pid) { \
            (event)->sid = BPF_CORE_READ(task, group_leader, tgid); \
        } \
        \
        /* Read process group ID */ \
        pgrp_pid = BPF_CORE_READ(signal, pids[PIDTYPE_PGID]); \
        if (pgrp_pid) { \
            (event)->pgid = BPF_CORE_READ(task, tgid); \
        } \
        \
        /* Read TTY name if available */ \
        tty = BPF_CORE_READ(signal, tty); \
        if (tty) { \
            bpf_probe_read_kernel_str(&(event)->tty, sizeof((event)->tty), \
                                       &tty->name); \
        } \
    } while (0)

// Generic macro to fill namespace information for container detection
// Reads PID, mount, and network namespace inodes from task->nsproxy
#define FILL_NAMESPACE_INFO(event, task) \
    do { \
        struct nsproxy *nsproxy; \
        struct pid_namespace *pid_ns; \
        struct mnt_namespace *mnt_ns; \
        struct net *net_ns; \
        \
        /* Initialize to init namespace values (host) */ \
        (event)->pid_ns = PROC_PID_INIT_INO; \
        (event)->mnt_ns = PROC_MNT_INIT_INO; \
        (event)->net_ns = PROC_NET_INIT_INO; \
        \
        /* Read nsproxy */ \
        nsproxy = BPF_CORE_READ(task, nsproxy); \
        if (!nsproxy) \
            break; \
        \
        /* Read PID namespace inode */ \
        pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children); \
        if (pid_ns) { \
            (event)->pid_ns = BPF_CORE_READ(pid_ns, ns.inum); \
        } \
        \
        /* Read mount namespace inode */ \
        mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns); \
        if (mnt_ns) { \
            (event)->mnt_ns = BPF_CORE_READ(mnt_ns, ns.inum); \
        } \
        \
        /* Read network namespace inode */ \
        net_ns = BPF_CORE_READ(nsproxy, net_ns); \
        if (net_ns) { \
            (event)->net_ns = BPF_CORE_READ(net_ns, ns.inum); \
        } \
    } while (0)

// Helper to read SUDO_UID from process environment
// Returns the original UID before sudo, or 0 if not running via sudo
// Only checks processes running as root (uid 0) for performance
//
// Uses a simple approach: read 48 bytes and search for the exact 10-byte
// sequence "\0SUDO_UID=" using memcmp-style comparison via helper.
static __always_inline __u32 read_sudo_uid(struct task_struct *task)
{
    struct mm_struct *mm;
    unsigned long env_start, env_end;
    // Use smaller buffer and fewer iterations
    char buf[48];
    int ret;

    mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return 0;

    env_start = BPF_CORE_READ(mm, env_start);
    env_end = BPF_CORE_READ(mm, env_end);

    if (env_start == 0 || env_end <= env_start)
        return 0;

    // Scan from 1.5KB to 3KB in 32-byte overlapping chunks
    // SUDO_UID is typically around 2-2.5KB after LS_COLORS
    #pragma unroll
    for (int chunk = 0; chunk < 48; chunk++) {
        unsigned long off = env_start + 1536 + chunk * 32;
        if (off >= env_end)
            return 0;

        ret = bpf_probe_read_user(buf, sizeof(buf), (void *)off);
        if (ret < 0)
            return 0;

        // Check positions 0-31 for "\0SUDO_UID=" pattern
        // Unrolled to avoid nested loop complexity
        #define CHECK_POS(p) \
            if (buf[p] == '\0' && buf[p+1] == 'S' && buf[p+2] == 'U' && \
                buf[p+3] == 'D' && buf[p+4] == 'O' && buf[p+5] == '_' && \
                buf[p+6] == 'U' && buf[p+7] == 'I' && buf[p+8] == 'D' && \
                buf[p+9] == '=') { \
                __u32 uid = 0; \
                if (buf[p+10] >= '0' && buf[p+10] <= '9') uid = buf[p+10] - '0'; else return uid; \
                if (buf[p+11] >= '0' && buf[p+11] <= '9') uid = uid*10 + buf[p+11] - '0'; else return uid; \
                if (buf[p+12] >= '0' && buf[p+12] <= '9') uid = uid*10 + buf[p+12] - '0'; else return uid; \
                if (buf[p+13] >= '0' && buf[p+13] <= '9') uid = uid*10 + buf[p+13] - '0'; else return uid; \
                if (buf[p+14] >= '0' && buf[p+14] <= '9') uid = uid*10 + buf[p+14] - '0'; else return uid; \
                if (buf[p+15] >= '0' && buf[p+15] <= '9') uid = uid*10 + buf[p+15] - '0'; \
                return uid; \
            }

        CHECK_POS(0);  CHECK_POS(1);  CHECK_POS(2);  CHECK_POS(3);
        CHECK_POS(4);  CHECK_POS(5);  CHECK_POS(6);  CHECK_POS(7);
        CHECK_POS(8);  CHECK_POS(9);  CHECK_POS(10); CHECK_POS(11);
        CHECK_POS(12); CHECK_POS(13); CHECK_POS(14); CHECK_POS(15);
        CHECK_POS(16); CHECK_POS(17); CHECK_POS(18); CHECK_POS(19);
        CHECK_POS(20); CHECK_POS(21); CHECK_POS(22); CHECK_POS(23);
        CHECK_POS(24); CHECK_POS(25); CHECK_POS(26); CHECK_POS(27);
        CHECK_POS(28); CHECK_POS(29); CHECK_POS(30); CHECK_POS(31);

        #undef CHECK_POS
    }

    return 0;
}

// ============================================================================
// PROCESS MONITORING
// ============================================================================

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task;
    struct process_event *event;
    u64 pid_tgid;
    u32 pid, uid;

    task = (struct task_struct *)bpf_get_current_task();

    // Check if this is a thread (if thread filtering is enabled)
    if (is_thread())
        return 0;

    // Check session filtering (TTY requirement)
    if (!should_monitor_session(task))
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    uid = bpf_get_current_uid_gid();

    // Check if UID should be monitored
    if (!should_monitor_uid(uid))
        return 0;

    // Rate limiting to prevent event flooding
    if (should_rate_limit(uid))
        return 0;

    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = EVENT_PROCESS_EXEC;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->uid = uid;
    event->gid = bpf_get_current_uid_gid() >> 32;

    // Fill session info (sid, pgid, tty)
    fill_session_info(event, task);

    // Fill namespace info (pid_ns, mnt_ns, net_ns)
    FILL_NAMESPACE_INFO(event, task);

    // Check for sudo context (only for root processes)
    if (uid == 0) {
        event->sudo_uid = read_sudo_uid(task);
    } else {
        event->sudo_uid = 0;
    }

    // Read command name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Read filename from tracepoint's dynamic data
    unsigned short offset = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&event->filename, sizeof(event->filename),
                       (void *)ctx + offset);

    // Initialize other fields
    event->cmdline[0] = '\0';
    event->exit_code = 0;

    // Submit event
    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct task_struct *task;
    struct process_event *event;
    u64 pid_tgid;
    u32 pid, uid;

    task = (struct task_struct *)bpf_get_current_task();

    // Check if this is a thread (if thread filtering is enabled)
    if (is_thread())
        return 0;

    if (!should_monitor_session(task))
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    uid = bpf_get_current_uid_gid();

    // Check if UID should be monitored
    if (!should_monitor_uid(uid))
        return 0;

    // Rate limiting to prevent event flooding
    if (should_rate_limit(uid))
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = EVENT_PROCESS_EXIT;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->uid = bpf_get_current_uid_gid();
    event->gid = bpf_get_current_uid_gid() >> 32;
    event->exit_code = BPF_CORE_READ(task, exit_code);

    // Fill session info (sid, pgid, tty)
    fill_session_info(event, task);

    // Fill namespace info (pid_ns, mnt_ns, net_ns)
    FILL_NAMESPACE_INFO(event, task);

    // sudo_uid not tracked for exit (already logged at exec)
    event->sudo_uid = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Initialize other fields
    event->filename[0] = '\0';
    event->cmdline[0] = '\0';

    bpf_ringbuf_submit(event, 0);

    return 0;
}

// ============================================================================
// FILE MONITORING
// ============================================================================

// Check if path is in /var/log/ directory (T1070.001 - Log Tampering)
static __always_inline int is_log_file(const char *path)
{
    // Check for /var/log/ prefix (10 chars: /var/log/ + at least one char)
    if (path[0] == '/' && path[1] == 'v' && path[2] == 'a' && path[3] == 'r' &&
        path[4] == '/' && path[5] == 'l' && path[6] == 'o' && path[7] == 'g' &&
        path[8] == '/' && path[9] != '\0') {
        return 1;
    }
    return 0;
}

// Check if process is a whitelisted log manager (allowed to modify /var/log/*)
static __always_inline int is_legit_log_manager(const char *comm)
{
    // logrotate
    if (comm[0] == 'l' && comm[1] == 'o' && comm[2] == 'g' && comm[3] == 'r' &&
        comm[4] == 'o' && comm[5] == 't' && comm[6] == 'a' && comm[7] == 't' &&
        comm[8] == 'e' && comm[9] == '\0') {
        return 1;
    }

    // rsyslogd
    if (comm[0] == 'r' && comm[1] == 's' && comm[2] == 'y' && comm[3] == 's' &&
        comm[4] == 'l' && comm[5] == 'o' && comm[6] == 'g' && comm[7] == 'd' &&
        comm[8] == '\0') {
        return 1;
    }

    // systemd-journal
    if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 't' &&
        comm[4] == 'e' && comm[5] == 'm' && comm[6] == 'd' && comm[7] == '-' &&
        comm[8] == 'j' && comm[9] == 'o' && comm[10] == 'u' && comm[11] == 'r' &&
        comm[12] == 'n' && comm[13] == 'a' && comm[14] == 'l') {
        return 1;  // matches systemd-journal* (truncated at 15 chars)
    }

    // syslog-ng
    if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 'l' &&
        comm[4] == 'o' && comm[5] == 'g' && comm[6] == '-' && comm[7] == 'n' &&
        comm[8] == 'g' && comm[9] == '\0') {
        return 1;
    }

    // auditd
    if (comm[0] == 'a' && comm[1] == 'u' && comm[2] == 'd' && comm[3] == 'i' &&
        comm[4] == 't' && comm[5] == 'd' && comm[6] == '\0') {
        return 1;
    }

    // linmond (LinMon itself)
    if (comm[0] == 'l' && comm[1] == 'i' && comm[2] == 'n' && comm[3] == 'm' &&
        comm[4] == 'o' && comm[5] == 'n' && comm[6] == 'd' && comm[7] == '\0') {
        return 1;
    }

    return 0;  // Not a whitelisted log manager
}

// Helper function for openat monitoring (shared between tracepoint and kprobe)
static __always_inline int handle_openat_common(const char *filename, int flags)
{
    __u32 uid = bpf_get_current_uid_gid();
    struct file_event *event;
    struct task_struct *task;

    // Check UID filtering
    if (!should_monitor_uid(uid))
        return 0;

    // Rate limiting
    if (should_rate_limit(uid))
        return 0;

    // Only log if opening for write or create
    if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)))
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    event->type = (flags & O_CREAT) ? EVENT_FILE_CREATE : EVENT_FILE_MODIFY;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;
    event->flags = flags;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint version (Ubuntu/modern kernels)
SEC("tp/syscalls/sys_enter_openat")
int handle_openat_tp(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];
    int flags = (int)ctx->args[2];
    return handle_openat_common(filename, flags);
}

// Kprobe version (RHEL 9 fallback when syscall tracepoints are blocked)
SEC("kprobe/__x64_sys_openat")
int handle_openat_kp(struct pt_regs *ctx)
{
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    int flags = (int)PT_REGS_PARM3(ctx);
    return handle_openat_common(filename, flags);
}

// Helper function for unlinkat monitoring (shared between tracepoint and kprobe)
static __always_inline int handle_unlinkat_common(const char *filename)
{
    __u32 uid = bpf_get_current_uid_gid();
    char path[32];  // Only need to check /var/log/ prefix
    char comm[TASK_COMM_LEN];
    struct task_struct *task;

    if (!should_monitor_uid(uid))
        return 0;

    if (should_rate_limit(uid))
        return 0;

    // Read path to check if it's a log file
    if (bpf_probe_read_user_str(path, sizeof(path), filename) < 0)
        return 0;

    // Check for log file deletion (T1070.001 - Log Clearing)
    if (is_log_file(path)) {
        // Check if this is a whitelisted log manager
        bpf_get_current_comm(&comm, sizeof(comm));
        if (is_legit_log_manager(comm))
            goto regular_file_delete;  // Log as normal file delete, not security event

        // Suspicious log file deletion - log as security event
        struct security_event *sec_event = bpf_ringbuf_reserve(&events, sizeof(*sec_event), 0);
        if (!sec_event)
            return 0;

        task = (struct task_struct *)bpf_get_current_task();

        sec_event->type = EVENT_SECURITY_LOG_TAMPER;
        sec_event->timestamp = bpf_ktime_get_ns();
        sec_event->pid = bpf_get_current_pid_tgid() >> 32;
        sec_event->uid = uid;

        // Fill process context (ppid, sid, pgid, tty)
        FILL_PROCESS_CONTEXT(sec_event, task);
        sec_event->target_pid = 0;
        sec_event->flags = 0;
        sec_event->port = 0;
        sec_event->family = 0;
        sec_event->extra = 2;  // 2=delete via unlink (1=truncate via O_TRUNC)
        bpf_get_current_comm(&sec_event->comm, sizeof(sec_event->comm));
        bpf_probe_read_user_str(&sec_event->filename, sizeof(sec_event->filename), filename);

        bpf_ringbuf_submit(sec_event, 0);
        return 0;
    }

regular_file_delete:
    ;  // Empty statement required after label (C99/C11)
    // Regular file deletion (not a log file, or whitelisted log manager)
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_FILE_DELETE;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;
    event->flags = 0;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint version (Ubuntu/modern kernels)
SEC("tp/syscalls/sys_enter_unlinkat")
int handle_unlinkat_tp(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];
    return handle_unlinkat_common(filename);
}

// Kprobe version (RHEL 9 fallback when syscall tracepoints are blocked)
SEC("kprobe/__x64_sys_unlinkat")
int handle_unlinkat_kp(struct pt_regs *ctx)
{
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    return handle_unlinkat_common(filename);
}

// ============================================================================
// NETWORK MONITORING
// ============================================================================

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect_enter, struct sock *sk)
{
    __u32 uid = bpf_get_current_uid_gid();
    struct network_event *event;
    struct task_struct *task;
    __u16 family, dport;

    if (!should_monitor_uid(uid))
        return 0;

    // Rate limiting to prevent event flooding
    if (should_rate_limit(uid))
        return 0;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;  // Only IPv4 and IPv6

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_NET_CONNECT_TCP;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->family = family;
    event->protocol = IPPROTO_TCP;
    event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    event->dport = __bpf_ntohs(dport);

    // Read addresses based on family
    if (family == AF_INET) {
        // IPv4 - store in first 4 bytes
        __u32 saddr4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 daddr4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);

        // Skip if destination address is not set yet (0.0.0.0)
        // This happens when kprobe fires too early in connection process
        if (daddr4 == 0) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }

        // Check CIDR filtering - ignore if destination is in filtered range
        if (should_ignore_network(daddr4)) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }

        __builtin_memcpy(event->saddr, &saddr4, 4);
        __builtin_memcpy(event->daddr, &daddr4, 4);
    } else if (family == AF_INET6) {
        // IPv6 - read full 16 bytes
        BPF_CORE_READ_INTO(&event->saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);

        // Skip if destination address is all zeros (::)
        bool all_zero = true;
        for (int i = 0; i < 16; i++) {
            if (event->daddr[i] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Some kernels use tcp_v4_connect for IPv4 specifically
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_enter, struct sock *sk)
{
    __u32 uid = bpf_get_current_uid_gid();
    struct network_event *event;
    struct task_struct *task;
    __u16 family, dport;

    if (!should_monitor_uid(uid))
        return 0;

    // Rate limiting to prevent event flooding
    if (should_rate_limit(uid))
        return 0;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;  // Only IPv4 and IPv6

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_NET_CONNECT_TCP;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->family = family;
    event->protocol = IPPROTO_TCP;
    event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    event->dport = __bpf_ntohs(dport);

    // Read addresses based on family
    if (family == AF_INET) {
        // IPv4 - store in first 4 bytes
        __u32 saddr4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 daddr4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);

        // Skip if destination address is not set yet (0.0.0.0)
        // This happens when kprobe fires too early in connection process
        if (daddr4 == 0) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }

        // Check CIDR filtering - ignore if destination is in filtered range
        if (should_ignore_network(daddr4)) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }

        __builtin_memcpy(event->saddr, &saddr4, 4);
        __builtin_memcpy(event->daddr, &daddr4, 4);
    } else if (family == AF_INET6) {
        // IPv6 - read full 16 bytes
        BPF_CORE_READ_INTO(&event->saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);

        // Skip if destination address is all zeros (::)
        bool all_zero = true;
        for (int i = 0; i < 16; i++) {
            if (event->daddr[i] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_accept_exit, struct sock *sk)
{
    __u32 uid = bpf_get_current_uid_gid();
    struct network_event *event;
    struct task_struct *task;
    __u16 family, dport;

    if (!sk)
        return 0;

    if (!should_monitor_uid(uid))
        return 0;

    // Rate limiting to prevent event flooding
    if (should_rate_limit(uid))
        return 0;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;  // Only IPv4 and IPv6

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_NET_ACCEPT_TCP;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->family = family;
    event->protocol = IPPROTO_TCP;
    event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    event->dport = __bpf_ntohs(dport);

    // Read addresses based on family
    if (family == AF_INET) {
        // IPv4 - store in first 4 bytes
        __u32 saddr4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 daddr4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);

        // Skip if destination address is not set yet (0.0.0.0)
        // This happens when kprobe fires too early in connection process
        if (daddr4 == 0) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }

        // Check CIDR filtering - ignore if destination is in filtered range
        if (should_ignore_network(daddr4)) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }

        __builtin_memcpy(event->saddr, &saddr4, 4);
        __builtin_memcpy(event->daddr, &daddr4, 4);
    } else if (family == AF_INET6) {
        // IPv6 - read full 16 bytes
        BPF_CORE_READ_INTO(&event->saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);

        // Skip if destination address is all zeros (::)
        bool all_zero = true;
        for (int i = 0; i < 16; i++) {
            if (event->daddr[i] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ============================================================================
// UDP MONITORING
// ============================================================================

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg_enter, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u32 uid = bpf_get_current_uid_gid();
    struct network_event *event;
    struct task_struct *task;
    __u16 family, dport;
    struct sockaddr_in *sin;

    if (!should_monitor_uid(uid))
        return 0;

    // Rate limiting to prevent event flooding
    if (should_rate_limit(uid))
        return 0;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_NET_SEND_UDP;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->family = family;
    event->protocol = IPPROTO_UDP;
    event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    // For UDP, get destination from msghdr if available
    if (family == AF_INET) {
        sin = (struct sockaddr_in *)BPF_CORE_READ(msg, msg_name);
        if (sin) {
            __u32 saddr4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            __u32 daddr4;
            __u16 dport_be;

            bpf_probe_read_kernel(&daddr4, sizeof(daddr4), &sin->sin_addr.s_addr);
            bpf_probe_read_kernel(&dport_be, sizeof(dport_be), &sin->sin_port);

            // Skip if no destination
            if (daddr4 == 0) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }

            // Check CIDR filtering - ignore if destination is in filtered range
            if (should_ignore_network(daddr4)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }

            __builtin_memcpy(event->saddr, &saddr4, 4);
            __builtin_memcpy(event->daddr, &daddr4, 4);
            event->dport = __bpf_ntohs(dport_be);
        } else {
            // If no msg_name, try to get from socket (connected UDP)
            __u32 saddr4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            __u32 daddr4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            __u16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);

            if (daddr4 == 0) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }

            // Check CIDR filtering - ignore if destination is in filtered range
            if (should_ignore_network(daddr4)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }

            __builtin_memcpy(event->saddr, &saddr4, 4);
            __builtin_memcpy(event->daddr, &daddr4, 4);
            event->dport = __bpf_ntohs(dport_be);
        }
    } else if (family == AF_INET6) {
        // For IPv6, try connected socket first
        BPF_CORE_READ_INTO(&event->saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
        dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        event->dport = __bpf_ntohs(dport);

        // Check if destination is set
        bool all_zero = true;
        for (int i = 0; i < 16; i++) {
            if (event->daddr[i] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(udpv6_sendmsg_enter, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u32 uid = bpf_get_current_uid_gid();
    struct network_event *event;
    struct task_struct *task;
    __u16 family, dport;

    if (!should_monitor_uid(uid))
        return 0;

    // Rate limiting
    if (should_rate_limit(uid))
        return 0;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET6)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_NET_SEND_UDP;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->family = family;
    event->protocol = IPPROTO_UDP;
    event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    // Read IPv6 addresses from socket
    BPF_CORE_READ_INTO(&event->saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    event->dport = __bpf_ntohs(dport);

    // Check if destination is set
    bool all_zero = true;
    for (int i = 0; i < 16; i++) {
        if (event->daddr[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ============================================================================
// VSOCK MONITORING (VM/Container Communication)
// ============================================================================

SEC("kprobe/vsock_connect")
int BPF_KPROBE(vsock_connect_enter, struct socket *sock, struct sockaddr *addr, int addr_len)
{
    __u32 uid = bpf_get_current_uid_gid();
    struct network_event *event;
    struct task_struct *task;
    struct sock *sk;
    __u16 family;

    if (!should_monitor_uid(uid))
        return 0;

    // Rate limiting
    if (should_rate_limit(uid))
        return 0;

    // Read socket pointer
    sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_VSOCK)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_NET_VSOCK_CONNECT;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->family = AF_VSOCK;
    event->protocol = 0;  // vsock doesn't use protocol field

    // For vsock: CID (Context ID) is like an IP address, port is like TCP/UDP port
    // Read local CID and port from socket
    __u32 local_cid = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);  // Local CID
    __u32 remote_cid = BPF_CORE_READ(sk, __sk_common.skc_daddr);     // Remote CID

    // Store CIDs in first 4 bytes of address fields
    __builtin_memcpy(event->saddr, &local_cid, 4);
    __builtin_memcpy(event->daddr, &remote_cid, 4);

    // Read ports
    event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
    event->dport = __bpf_ntohs(dport_be);

    // Skip if destination CID is not set (0)
    if (remote_cid == 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ============================================================================
// PRIVILEGE ESCALATION MONITORING
// ============================================================================

SEC("tp/sched/sched_process_exec")
int handle_privilege_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct privilege_event *event;
    struct task_struct *task;
    char comm[TASK_COMM_LEN];
    __u64 pid_tgid;
    __u32 pid;
    __u64 uid_gid;

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    uid_gid = bpf_get_current_uid_gid();

    bpf_get_current_comm(&comm, sizeof(comm));

    // Check if this is sudo, su, or pkexec
    bool is_priv = false;
    if (comm[0] == 's' && comm[1] == 'u') {
        if ((comm[2] == 'd' && comm[3] == 'o' && comm[4] == '\0') ||  // sudo
            (comm[2] == '\0')) {  // su
            is_priv = true;
        }
    } else if (comm[0] == 'p' && comm[1] == 'k' && comm[2] == 'e' &&
               comm[3] == 'x' && comm[4] == 'e' && comm[5] == 'c') {  // pkexec
        is_priv = true;
    }

    if (!is_priv)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_PRIV_SUDO;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->old_uid = uid_gid & 0xFFFFFFFF;
    event->old_gid = uid_gid >> 32;
    event->new_uid = 0;  // Will be set if/when setuid is called
    event->new_gid = 0;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);

    __builtin_memcpy(&event->comm, comm, TASK_COMM_LEN);

    // Read filename from tracepoint
    unsigned short offset = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&event->target_comm, sizeof(event->target_comm),
                       (void *)ctx + offset);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Helper function for setuid monitoring (shared between tracepoint and kprobe)
static __always_inline int handle_setuid_common(__u32 new_uid)
{
    struct privilege_event *event;
    struct task_struct *task;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 old_uid = uid_gid & 0xFFFFFFFF;

    // Only log if changing to a different UID
    if (old_uid == new_uid)
        return 0;

    // Log if changing to root or from root
    if (old_uid != 0 && new_uid != 0)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_PRIV_SETUID;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->old_uid = old_uid;
    event->new_uid = new_uid;
    event->old_gid = uid_gid >> 32;
    event->new_gid = uid_gid >> 32;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->target_comm[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint version (Ubuntu/modern kernels)
SEC("tp/syscalls/sys_enter_setuid")
int handle_setuid_tp(struct trace_event_raw_sys_enter *ctx)
{
    __u32 new_uid = (__u32)ctx->args[0];
    return handle_setuid_common(new_uid);
}

// Kprobe version (RHEL 9 fallback when syscall tracepoints are blocked)
SEC("kprobe/__x64_sys_setuid")
int handle_setuid_kp(struct pt_regs *ctx)
{
    __u32 new_uid = (__u32)PT_REGS_PARM1(ctx);
    return handle_setuid_common(new_uid);
}

// Helper function for setgid monitoring (shared between tracepoint and kprobe)
static __always_inline int handle_setgid_common(__u32 new_gid)
{
    struct privilege_event *event;
    struct task_struct *task;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 old_gid = uid_gid >> 32;

    // Only log if changing to a different GID
    if (old_gid == new_gid)
        return 0;

    // Log if changing to root (GID 0) or from root
    if (old_gid != 0 && new_gid != 0)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_PRIV_SETGID;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->old_uid = uid_gid & 0xFFFFFFFF;
    event->new_uid = uid_gid & 0xFFFFFFFF;
    event->old_gid = old_gid;
    event->new_gid = new_gid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->target_comm[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint version (Ubuntu/modern kernels)
SEC("tp/syscalls/sys_enter_setgid")
int handle_setgid_tp(struct trace_event_raw_sys_enter *ctx)
{
    __u32 new_gid = (__u32)ctx->args[0];
    return handle_setgid_common(new_gid);
}

// Kprobe version (RHEL 9 fallback when syscall tracepoints are blocked)
SEC("kprobe/__x64_sys_setgid")
int handle_setgid_kp(struct pt_regs *ctx)
{
    __u32 new_gid = (__u32)PT_REGS_PARM1(ctx);
    return handle_setgid_common(new_gid);
}

// ============================================================================
// SECURITY MONITORING - Process Injection (MITRE ATT&CK T1055)
// ============================================================================

// ptrace request values we care about for security monitoring
// PTRACE_ATTACH = 16 - attach to process for debugging
// PTRACE_SEIZE = 16902 - modern attach without stopping
// PTRACE_POKETEXT = 4 - write to text segment (code injection)
// PTRACE_POKEDATA = 5 - write to data segment
#define PTRACE_POKETEXT 4
#define PTRACE_POKEDATA 5
#define PTRACE_ATTACH 16
#define PTRACE_SEIZE 16902

static __always_inline int handle_ptrace_common(long request, __u32 target_pid)
{
    // Only log dangerous requests that could indicate process injection
    if (request != PTRACE_ATTACH && request != PTRACE_SEIZE &&
        request != PTRACE_POKETEXT && request != PTRACE_POKEDATA)
        return 0;

    __u32 uid = bpf_get_current_uid_gid();

    if (!should_monitor_uid(uid))
        return 0;

    // Rate limiting
    if (should_rate_limit(uid))
        return 0;

    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_SECURITY_PTRACE;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);
    event->target_pid = target_pid;
    event->flags = (__u32)request;
    event->port = 0;
    event->family = 0;
    event->extra = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_ptrace")
int handle_ptrace_tp(struct trace_event_raw_sys_enter *ctx)
{
    long request = (long)ctx->args[0];
    __u32 target_pid = (__u32)ctx->args[1];
    return handle_ptrace_common(request, target_pid);
}

SEC("kprobe/__x64_sys_ptrace")
int handle_ptrace_kp(struct pt_regs *ctx)
{
    long request = (long)PT_REGS_PARM1(ctx);
    __u32 target_pid = (__u32)PT_REGS_PARM2(ctx);
    return handle_ptrace_common(request, target_pid);
}

// ============================================================================
// SECURITY MONITORING - Kernel Module Loading (MITRE ATT&CK T1547.006)
// ============================================================================

// finit_module is the modern syscall (loads module from file descriptor)
SEC("tp/syscalls/sys_enter_finit_module")
int handle_finit_module_tp(struct trace_event_raw_sys_enter *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();

    // Module loading is always security-relevant (only root can do it anyway)
    // Don't apply UID filtering - we want to know about all module loads

    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_SECURITY_MODULE;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);
    event->target_pid = 0;
    event->flags = (__u32)ctx->args[2];  // Module flags
    event->port = 0;
    event->family = 0;
    event->extra = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';  // Can't easily get module name from fd

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/__x64_sys_finit_module")
int handle_finit_module_kp(struct pt_regs *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();

    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_SECURITY_MODULE;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);
    event->target_pid = 0;
    event->flags = (__u32)PT_REGS_PARM3(ctx);
    event->port = 0;
    event->family = 0;
    event->extra = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// init_module is the legacy syscall (loads module from memory buffer)
SEC("tp/syscalls/sys_enter_init_module")
int handle_init_module_tp(struct trace_event_raw_sys_enter *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();

    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_SECURITY_MODULE;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);
    event->target_pid = 0;
    event->flags = 0;  // Legacy syscall doesn't have flags
    event->port = 0;
    event->family = 0;
    event->extra = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/__x64_sys_init_module")
int handle_init_module_kp(struct pt_regs *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();

    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_SECURITY_MODULE;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);
    event->target_pid = 0;
    event->flags = 0;
    event->port = 0;
    event->family = 0;
    event->extra = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ============================================================================
// SECURITY MONITORING - Fileless Malware Detection (MITRE ATT&CK T1620)
// ============================================================================

static __always_inline int handle_memfd_common(const char *name, unsigned int flags)
{
    __u32 uid = bpf_get_current_uid_gid();

    if (!should_monitor_uid(uid))
        return 0;

    // Rate limiting
    if (should_rate_limit(uid))
        return 0;

    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_SECURITY_MEMFD;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);
    event->target_pid = 0;
    event->flags = flags;
    event->port = 0;
    event->family = 0;
    event->extra = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Read memfd name from userspace
    if (name) {
        bpf_probe_read_user_str(&event->filename, sizeof(event->filename), name);
    } else {
        event->filename[0] = '\0';
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_memfd_create")
int handle_memfd_create_tp(struct trace_event_raw_sys_enter *ctx)
{
    const char *name = (const char *)ctx->args[0];
    unsigned int flags = (unsigned int)ctx->args[1];
    return handle_memfd_common(name, flags);
}

SEC("kprobe/__x64_sys_memfd_create")
int handle_memfd_create_kp(struct pt_regs *ctx)
{
    const char *name = (const char *)PT_REGS_PARM1(ctx);
    unsigned int flags = (unsigned int)PT_REGS_PARM2(ctx);
    return handle_memfd_common(name, flags);
}

// ============================================================================
// SECURITY MONITORING - Bind Shell Detection (MITRE ATT&CK T1571)
// ============================================================================

// bind() syscall - detects servers listening on ports (bind shells, C2)
static __always_inline int handle_bind_common(int fd, struct sockaddr *addr, int addrlen)
{
    __u32 uid = bpf_get_current_uid_gid();

    if (!should_monitor_uid(uid))
        return 0;

    // Rate limiting
    if (should_rate_limit(uid))
        return 0;

    // Read address family
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

    // Only monitor IPv4 and IPv6
    if (family != AF_INET && family != AF_INET6)
        return 0;

    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_SECURITY_BIND;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);
    event->target_pid = fd;  // Store fd in target_pid field
    event->flags = 0;
    event->family = family;
    event->extra = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';

    // Extract port based on address family
    if (family == AF_INET) {
        struct sockaddr_in sin;
        bpf_probe_read_user(&sin, sizeof(sin), addr);
        event->port = __bpf_ntohs(sin.sin_port);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 sin6;
        bpf_probe_read_user(&sin6, sizeof(sin6), addr);
        event->port = __bpf_ntohs(sin6.sin6_port);
    }

    // Skip ephemeral/dynamic ports (typically >= 32768) unless port 0
    // Port 0 means OS assigns a port, which is normal client behavior
    if (event->port == 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_bind")
int handle_bind_tp(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    int addrlen = (int)ctx->args[2];
    return handle_bind_common(fd, addr, addrlen);
}

SEC("kprobe/__x64_sys_bind")
int handle_bind_kp(struct pt_regs *ctx)
{
    int fd = (int)PT_REGS_PARM1(ctx);
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    int addrlen = (int)PT_REGS_PARM3(ctx);
    return handle_bind_common(fd, addr, addrlen);
}

// ============================================================================
// SECURITY MONITORING - Container Escape Detection (MITRE ATT&CK T1611)
// ============================================================================

// unshare() syscall - detects namespace manipulation (container escapes)
// Key flags to watch:
// CLONE_NEWNS    = 0x00020000 - Mount namespace
// CLONE_NEWPID   = 0x20000000 - PID namespace
// CLONE_NEWNET   = 0x40000000 - Network namespace
// CLONE_NEWUSER  = 0x10000000 - User namespace
// CLONE_NEWUTS   = 0x04000000 - UTS namespace
// CLONE_NEWIPC   = 0x08000000 - IPC namespace
// CLONE_NEWCGROUP= 0x02000000 - Cgroup namespace

static __always_inline int handle_unshare_common(unsigned long flags)
{
    __u32 uid = bpf_get_current_uid_gid();

    if (!should_monitor_uid(uid))
        return 0;

    // Rate limiting
    if (should_rate_limit(uid))
        return 0;

    // Only log if namespace-related flags are set
    // These are the interesting ones for security monitoring
    unsigned long ns_flags = 0x7E020000;  // All CLONE_NEW* flags
    if (!(flags & ns_flags))
        return 0;

    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_SECURITY_UNSHARE;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);
    event->target_pid = 0;
    event->flags = (__u32)flags;
    event->port = 0;
    event->family = 0;
    event->extra = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_unshare")
int handle_unshare_tp(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long flags = (unsigned long)ctx->args[0];
    return handle_unshare_common(flags);
}

SEC("kprobe/__x64_sys_unshare")
int handle_unshare_kp(struct pt_regs *ctx)
{
    unsigned long flags = (unsigned long)PT_REGS_PARM1(ctx);
    return handle_unshare_common(flags);
}

// ============================================================================
// SECURITY MONITORING - Fileless Execution (MITRE ATT&CK T1620)
// ============================================================================

// execveat() syscall - fd-based execution, enables truly fileless malware
// AT_EMPTY_PATH (0x1000) with empty pathname = execute fd directly
// This completes memfd_create detection: memfd_create() -> write ELF -> execveat()

static __always_inline int handle_execveat_common(int dirfd, const char *pathname,
                                                   int flags)
{
    __u32 uid = bpf_get_current_uid_gid();

    if (!should_monitor_uid(uid))
        return 0;

    // Rate limiting
    if (should_rate_limit(uid))
        return 0;

    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_SECURITY_EXECVEAT;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);
    event->target_pid = dirfd;  // Store fd in target_pid
    event->flags = 0;
    event->port = 0;
    event->family = 0;
    event->extra = (__u32)flags;  // AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW, etc.
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Read pathname if available
    if (pathname) {
        bpf_probe_read_user_str(&event->filename, sizeof(event->filename), pathname);
    } else {
        event->filename[0] = '\0';
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_execveat")
int handle_execveat_tp(struct trace_event_raw_sys_enter *ctx)
{
    int dirfd = (int)ctx->args[0];
    const char *pathname = (const char *)ctx->args[1];
    // args[2] = argv, args[3] = envp
    int flags = (int)ctx->args[4];
    return handle_execveat_common(dirfd, pathname, flags);
}

SEC("kprobe/__x64_sys_execveat")
int handle_execveat_kp(struct pt_regs *ctx)
{
    int dirfd = (int)PT_REGS_PARM1(ctx);
    const char *pathname = (const char *)PT_REGS_PARM2(ctx);
    // PARM3 = argv, PARM4 = envp
    int flags = (int)PT_REGS_PARM5(ctx);
    return handle_execveat_common(dirfd, pathname, flags);
}

// ============================================================================
// SECURITY MONITORING - eBPF Rootkit Detection (MITRE ATT&CK T1014)
// ============================================================================

// bpf() syscall - detects loading of BPF programs (potential rootkits)
// Key commands:
// BPF_PROG_LOAD = 5 - Load a BPF program (most interesting for rootkit detection)
// BPF_MAP_CREATE = 0 - Create a BPF map
// BPF_BTF_LOAD = 18 - Load BTF data

#define BPF_MAP_CREATE    0
#define BPF_PROG_LOAD     5
#define BPF_BTF_LOAD      18

static __always_inline int handle_bpf_common(int cmd, unsigned int attr_size)
{
    __u32 uid = bpf_get_current_uid_gid();

    // BPF operations require CAP_BPF/CAP_SYS_ADMIN, so usually uid=0
    // But we still want to log all BPF program loads for auditing

    // Rate limiting
    if (should_rate_limit(uid))
        return 0;

    // Only log interesting commands
    if (cmd != BPF_PROG_LOAD && cmd != BPF_MAP_CREATE && cmd != BPF_BTF_LOAD)
        return 0;

    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->type = EVENT_SECURITY_BPF;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);
    event->target_pid = 0;
    event->flags = 0;
    event->port = 0;
    event->family = 0;
    event->extra = (__u32)cmd;  // BPF command
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_bpf")
int handle_bpf_tp(struct trace_event_raw_sys_enter *ctx)
{
    int cmd = (int)ctx->args[0];
    unsigned int attr_size = (unsigned int)ctx->args[2];
    return handle_bpf_common(cmd, attr_size);
}

SEC("kprobe/__x64_sys_bpf")
int handle_bpf_kp(struct pt_regs *ctx)
{
    int cmd = (int)PT_REGS_PARM1(ctx);
    unsigned int attr_size = (unsigned int)PT_REGS_PARM3(ctx);
    return handle_bpf_common(cmd, attr_size);
}

// ============================================================================
// SECURITY MONITORING - Credential File Access (MITRE ATT&CK T1003.008)
// ============================================================================
// Monitors reads of /etc/shadow, /etc/gshadow - files that should only be
// accessed by authentication daemons. Whitelists legitimate processes.

// Check if comm starts with a given prefix (for whitelist checking)
// Uses direct byte comparison to avoid function call issues
#define COMM_STARTS_WITH(comm, str) ( \
    (str[0] == '\0') || \
    ((comm)[0] == (str)[0] && ((str)[1] == '\0' || \
    ((comm)[1] == (str)[1] && ((str)[2] == '\0' || \
    ((comm)[2] == (str)[2] && ((str)[3] == '\0' || \
    ((comm)[3] == (str)[3] && ((str)[4] == '\0' || \
    ((comm)[4] == (str)[4] && ((str)[5] == '\0' || \
    ((comm)[5] == (str)[5] && ((str)[6] == '\0' || \
    ((comm)[6] == (str)[6] && ((str)[7] == '\0' || \
    ((comm)[7] == (str)[7]))))))))))))))))

// Check if process is a legitimate credential reader
// Returns 1 if whitelisted (should NOT log), 0 if suspicious (should log)
static __always_inline int is_legit_cred_reader(const char *comm)
{
    // Whitelist of legitimate processes that read /etc/shadow
    // These are authentication daemons and password management tools
    // Using prefix matching for efficiency

    // Auth daemons
    if (comm[0] == 'l' && comm[1] == 'o' && comm[2] == 'g' &&
        comm[3] == 'i' && comm[4] == 'n') return 1;  // login
    if (comm[0] == 's' && comm[1] == 's' && comm[2] == 'h' &&
        comm[3] == 'd') return 1;  // sshd
    if (comm[0] == 's' && comm[1] == 'u' &&
        (comm[2] == '\0' || comm[2] == 'd')) return 1;  // su, sudo
    if (comm[0] == 'p' && comm[1] == 'a' && comm[2] == 's' &&
        comm[3] == 's' && comm[4] == 'w' && comm[5] == 'd') return 1;  // passwd

    // User management tools
    if (comm[0] == 'u' && comm[1] == 's' && comm[2] == 'e' &&
        comm[3] == 'r') return 1;  // useradd, usermod, userdel
    if (comm[0] == 'c' && comm[1] == 'h') {
        if (comm[2] == 'p' && comm[3] == 'a') return 1;  // chpasswd
        if (comm[2] == 'a' && comm[3] == 'g') return 1;  // chage
    }
    if (comm[0] == 'g' && comm[1] == 'r' && comm[2] == 'o' &&
        comm[3] == 'u' && comm[4] == 'p') return 1;  // groupadd, groupmod
    if (comm[0] == 'p' && comm[1] == 'w' && comm[2] == 'c' &&
        comm[3] == 'k') return 1;  // pwck
    if (comm[0] == 'g' && comm[1] == 'r' && comm[2] == 'p' &&
        comm[3] == 'c' && comm[4] == 'k') return 1;  // grpck

    // PAM / Auth helpers
    if (comm[0] == 'u' && comm[1] == 'n' && comm[2] == 'i' &&
        comm[3] == 'x' && comm[4] == '_') return 1;  // unix_chkpwd

    // System services
    if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' &&
        comm[3] == 't' && comm[4] == 'e' && comm[5] == 'm' &&
        comm[6] == 'd') return 1;  // systemd*
    if (comm[0] == 'p' && comm[1] == 'o' && comm[2] == 'l' &&
        comm[3] == 'k' && comm[4] == 'i' && comm[5] == 't') return 1;  // polkitd
    if (comm[0] == 's' && comm[1] == 's' && comm[2] == 's' &&
        comm[3] == 'd') return 1;  // sssd
    if (comm[0] == 'n' && comm[1] == 's' && comm[2] == 'c' &&
        comm[3] == 'd') return 1;  // nscd

    // Display managers
    if (comm[0] == 'g' && comm[1] == 'd' && comm[2] == 'm') return 1;  // gdm*
    if (comm[0] == 'l' && comm[1] == 'i' && comm[2] == 'g' &&
        comm[3] == 'h' && comm[4] == 't' && comm[5] == 'd' &&
        comm[6] == 'm') return 1;  // lightdm
    if (comm[0] == 's' && comm[1] == 'd' && comm[2] == 'd' &&
        comm[3] == 'm') return 1;  // sddm
    if (comm[0] == 'x' && comm[1] == 'd' && comm[2] == 'm') return 1;  // xdm

    // Cron/at
    if (comm[0] == 'c' && comm[1] == 'r' && comm[2] == 'o' &&
        comm[3] == 'n') return 1;  // cron
    if (comm[0] == 'a' && comm[1] == 't' && comm[2] == 'd') return 1;  // atd

    return 0;  // Not whitelisted - log it
}

// Check if path is a sensitive credential/auth file
// Returns file type:
//   0 = not sensitive
//   1 = /etc/shadow
//   2 = /etc/gshadow
//   3 = /etc/sudoers or /etc/sudoers.d/*
//   4 = /etc/ssh/* (SSH config files)
//   5 = /etc/pam.d/* (PAM config files)
//   6 = ~/.ssh/id_* (SSH private keys)
//   7 = ~/.ssh/authorized_keys (SSH authorized keys backdoor)
//   8 = ~/.ssh/config (SSH user config)
static __always_inline int get_cred_file_type(const char *path)
{
    // Check /etc/* files first
    if (path[0] == '/' && path[1] == 'e' && path[2] == 't' &&
        path[3] == 'c' && path[4] == '/') {

        // After /etc/ (index 5)
        char c5 = path[5];

        // Check for /etc/shadow
        if (c5 == 's' && path[6] == 'h' && path[7] == 'a' && path[8] == 'd' &&
            path[9] == 'o' && path[10] == 'w' && path[11] == '\0') {
            return 1;  // /etc/shadow
        }

        // Check for /etc/gshadow
        if (c5 == 'g' && path[6] == 's' && path[7] == 'h' && path[8] == 'a' &&
            path[9] == 'd' && path[10] == 'o' && path[11] == 'w' && path[12] == '\0') {
            return 2;  // /etc/gshadow
        }

        // Check for /etc/sudoers (exact) or /etc/sudoers.d/* (prefix)
        if (c5 == 's' && path[6] == 'u' && path[7] == 'd' && path[8] == 'o' &&
            path[9] == 'e' && path[10] == 'r' && path[11] == 's') {
            // /etc/sudoers (exact match)
            if (path[12] == '\0')
                return 3;
            // /etc/sudoers.d/* (directory prefix)
            if (path[12] == '.' && path[13] == 'd' && path[14] == '/')
                return 3;
        }

        // Check for /etc/ssh/* (prefix match)
        if (c5 == 's' && path[6] == 's' && path[7] == 'h' && path[8] == '/') {
            return 4;  // /etc/ssh/*
        }

        // Check for /etc/pam.d/* (prefix match)
        if (c5 == 'p' && path[6] == 'a' && path[7] == 'm' && path[8] == '.' &&
            path[9] == 'd' && path[10] == '/') {
            return 5;  // /etc/pam.d/*
        }

        return 0;  // Other /etc/ file
    }

    // Check for ~/.ssh/* patterns (scan entire path for /.ssh/ substring)
    // Need to scan because home directory path varies (/home/user, /root, etc.)
    #pragma unroll
    for (int i = 0; i < 16; i++) {  // Scan first 22 chars - covers /root/.ssh/, /home/u/.ssh/
        if (path[i] == '/' && path[i+1] == '.' &&
            path[i+2] == 's' && path[i+3] == 's' && path[i+4] == 'h' && path[i+5] == '/') {

            int ssh_start = i + 6;  // After /.ssh/

            // Check for id_rsa, id_ed25519, id_ecdsa (private keys)
            if (path[ssh_start] == 'i' && path[ssh_start+1] == 'd' && path[ssh_start+2] == '_') {
                // id_rsa*
                if (path[ssh_start+3] == 'r' && path[ssh_start+4] == 's' && path[ssh_start+5] == 'a') {
                    return 6;  // ssh_private_key
                }
                // id_ed25519*
                if (path[ssh_start+3] == 'e' && path[ssh_start+4] == 'd' && path[ssh_start+5] == '2' &&
                    path[ssh_start+6] == '5' && path[ssh_start+7] == '5' && path[ssh_start+8] == '1' &&
                    path[ssh_start+9] == '9') {
                    return 6;  // ssh_private_key
                }
                // id_ecdsa*
                if (path[ssh_start+3] == 'e' && path[ssh_start+4] == 'c' && path[ssh_start+5] == 'd' &&
                    path[ssh_start+6] == 's' && path[ssh_start+7] == 'a') {
                    return 6;  // ssh_private_key
                }
            }

            // Check for authorized_keys
            if (path[ssh_start] == 'a' && path[ssh_start+1] == 'u' && path[ssh_start+2] == 't' &&
                path[ssh_start+3] == 'h' && path[ssh_start+4] == 'o' && path[ssh_start+5] == 'r' &&
                path[ssh_start+6] == 'i' && path[ssh_start+7] == 'z' && path[ssh_start+8] == 'e' &&
                path[ssh_start+9] == 'd' && path[ssh_start+10] == '_' && path[ssh_start+11] == 'k' &&
                path[ssh_start+12] == 'e' && path[ssh_start+13] == 'y' && path[ssh_start+14] == 's') {
                return 7;  // ssh_authorized_keys
            }

            // Check for config
            if (path[ssh_start] == 'c' && path[ssh_start+1] == 'o' && path[ssh_start+2] == 'n' &&
                path[ssh_start+3] == 'f' && path[ssh_start+4] == 'i' && path[ssh_start+5] == 'g' &&
                path[ssh_start+6] == '\0') {
                return 8;  // ssh_user_config
            }

            return 0;  // Other file in .ssh directory
        }
    }

    return 0;  // Not a sensitive file
}

// Check if path is /etc/ld.so.preload
static __always_inline int is_ldpreload_file(const char *path)
{
    // Check for /etc/ld.so.preload (20 chars including null)
    if (path[0] == '/' && path[1] == 'e' && path[2] == 't' &&
        path[3] == 'c' && path[4] == '/' && path[5] == 'l' &&
        path[6] == 'd' && path[7] == '.' && path[8] == 's' &&
        path[9] == 'o' && path[10] == '.' && path[11] == 'p' &&
        path[12] == 'r' && path[13] == 'e' && path[14] == 'l' &&
        path[15] == 'o' && path[16] == 'a' && path[17] == 'd' &&
        path[18] == '\0') {
        return 1;
    }
    return 0;
}

// Unified handler for credential/ldpreload monitoring via openat
static __always_inline int handle_security_openat(int dfd, const char *pathname, int flags)
{
    char path[64];  // Only need to check start of path
    char comm[TASK_COMM_LEN];
    __u32 uid;
    int cred_type;
    
    if (!pathname)
        return 0;
    
    // Read the path from userspace
    if (bpf_probe_read_user_str(path, sizeof(path), pathname) < 0)
        return 0;
    
    // Check for LD_PRELOAD file WRITE (T1574.006)
    // Any write to /etc/ld.so.preload is highly suspicious
    if (is_ldpreload_file(path)) {
        // Only interested in writes (O_WRONLY, O_RDWR, O_CREAT, O_TRUNC)
        if (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) {
            uid = bpf_get_current_uid_gid();
            
            struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
            if (!event)
                return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            
            event->type = EVENT_SECURITY_LDPRELOAD;
            event->timestamp = bpf_ktime_get_ns();
            event->pid = bpf_get_current_pid_tgid() >> 32;
            event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);
            event->target_pid = 0;
            event->flags = flags;
            event->port = 0;
            event->family = 0;
            event->extra = 0;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            bpf_probe_read_user_str(&event->filename, sizeof(event->filename), pathname);
            
            bpf_ringbuf_submit(event, 0);
        }
        return 0;
    }
    
    // Check if this is a credential file
    cred_type = get_cred_file_type(path);

    // Check for credential file WRITE (T1098.001 - Account Manipulation)
    // Detects writes to /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers, etc.
    if (cred_type != 0 && (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC))) {
        uid = bpf_get_current_uid_gid();

        // Rate limit
        if (should_rate_limit(uid))
            return 0;

        // Log credential file write
        struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event)
            return 0;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();

        event->type = EVENT_SECURITY_CRED_WRITE;
        event->timestamp = bpf_ktime_get_ns();
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->uid = uid;

        // Fill process context (ppid, sid, pgid, tty)
        FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);
        event->target_pid = 0;
        event->flags = flags;
        event->port = 0;
        event->family = 0;
        event->extra = cred_type;  // 1=shadow, 2=gshadow, 3=sudoers, etc.
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        bpf_probe_read_user_str(&event->filename, sizeof(event->filename), pathname);

        bpf_ringbuf_submit(event, 0);
        return 0;  // Don't also log as READ
    }

    // Check for log file tampering (T1070.001 - Log Clearing)
    // Detect truncation of /var/log/* files (e.g., > /var/log/auth.log)
    if (is_log_file(path) && (flags & O_TRUNC)) {
        uid = bpf_get_current_uid_gid();

        // Rate limit
        if (should_rate_limit(uid))
            return 0;

        // Check if this is a whitelisted log manager
        bpf_get_current_comm(&comm, sizeof(comm));
        if (is_legit_log_manager(comm))
            return 0;  // Legitimate log rotation/management

        // Suspicious log file truncation - log it
        struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event)
            return 0;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();

        event->type = EVENT_SECURITY_LOG_TAMPER;
        event->timestamp = bpf_ktime_get_ns();
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->uid = uid;

        // Fill process context (ppid, sid, pgid, tty)
        FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);
        event->target_pid = 0;
        event->flags = flags;
        event->port = 0;
        event->family = 0;
        event->extra = 1;  // 1=truncate (other types TBD: 2=delete via unlink)
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        bpf_probe_read_user_str(&event->filename, sizeof(event->filename), pathname);

        bpf_ringbuf_submit(event, 0);
        return 0;
    }

    // Check for credential file READ (T1003.008)
    // Only monitor actual credential files
    if (cred_type == 0)
        return 0;  // Not a credential file

    // We want to detect READs - any open that's not purely write
    // O_RDONLY = 0, so check if NOT (O_WRONLY without O_RDWR)
    if ((flags & O_WRONLY) && !(flags & O_RDWR))
        return 0;  // Write-only, not interesting for credential theft
    
    uid = bpf_get_current_uid_gid();
    
    // Rate limit
    if (should_rate_limit(uid))
        return 0;
    
    // Get process name and check whitelist
    bpf_get_current_comm(&comm, sizeof(comm));
    if (is_legit_cred_reader(comm))
        return 0;  // Legitimate process, don't log
    
    // Suspicious credential file access - log it
    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    event->type = EVENT_SECURITY_CRED_READ;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);
    event->target_pid = 0;
    event->flags = flags;
    event->port = 0;
    event->family = 0;
    event->extra = cred_type;  // 1=shadow, 2=gshadow
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), pathname);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_security_openat_tp(struct trace_event_raw_sys_enter *ctx)
{
    int dfd = (int)ctx->args[0];
    const char *pathname = (const char *)ctx->args[1];
    int flags = (int)ctx->args[2];
    return handle_security_openat(dfd, pathname, flags);
}

SEC("kprobe/__x64_sys_openat")
int handle_security_openat_kp(struct pt_regs *ctx)
{
    int dfd = (int)PT_REGS_PARM1(ctx);
    const char *pathname = (const char *)PT_REGS_PARM2(ctx);
    int flags = (int)PT_REGS_PARM3(ctx);
    return handle_security_openat(dfd, pathname, flags);
}

// SUID/SGID manipulation detection (T1548.001)
// Detects chmod operations that set SUID (04000) or SGID (02000) bits
static __always_inline int handle_fchmodat_common(int dfd, const char *pathname, __u32 mode)
{
    char path[MAX_FILENAME_LEN];
    __u32 uid;

    if (!pathname)
        return 0;

    // Only interested in SUID (04000) or SGID (02000) changes
    if (!(mode & 06000))  // Check for S_ISUID | S_ISGID
        return 0;

    // Read path
    if (bpf_probe_read_user_str(path, sizeof(path), pathname) < 0)
        return 0;

    uid = bpf_get_current_uid_gid();

    // Rate limiting check
    if (should_rate_limit(uid))
        return 0;

    // Reserve event
    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    // Fill event
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->type = EVENT_SECURITY_SUID;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);

    event->target_pid = 0;
    event->flags = mode;  // Store new mode with SUID/SGID bits
    event->port = 0;
    event->family = 0;
    event->extra = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memcpy(event->filename, path, sizeof(event->filename));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_fchmodat")
int handle_fchmodat_tp(struct trace_event_raw_sys_enter *ctx)
{
    int dfd = (int)ctx->args[0];
    const char *pathname = (const char *)ctx->args[1];
    __u32 mode = (__u32)ctx->args[2];

    return handle_fchmodat_common(dfd, pathname, mode);
}

SEC("kprobe/__x64_sys_fchmodat")
int handle_fchmodat_kp(struct pt_regs *ctx)
{
    int dfd = (int)PT_REGS_PARM1(ctx);
    const char *pathname = (const char *)PT_REGS_PARM2(ctx);
    __u32 mode = (__u32)PT_REGS_PARM3(ctx);

    return handle_fchmodat_common(dfd, pathname, mode);
}
// Persistence mechanism detection (T1053, T1547)
// Check if path is a persistence location
// Returns persistence type:
//   0 = not persistence
//   1 = cron (/etc/cron.d/*, /var/spool/cron/*)
//   2 = systemd (/etc/systemd/system/*, /usr/lib/systemd/system/*)
//   3 = shell profile (~/.bashrc, ~/.profile, ~/.zshrc, etc.)
//   4 = init (/etc/rc.local, /etc/init.d/*)
//   5 = autostart (~/.config/autostart/*)
static __always_inline int get_persistence_type(const char *path)
{
    // Check /etc/* paths first
    if (path[0] == '/' && path[1] == 'e' && path[2] == 't' && path[3] == 'c' && path[4] == '/') {
        // /etc/cron.d/
        if (path[5] == 'c' && path[6] == 'r' && path[7] == 'o' && path[8] == 'n' &&
            path[9] == '.' && path[10] == 'd' && path[11] == '/') {
            return 1;
        }

        // /etc/systemd/system/
        if (path[5] == 's' && path[6] == 'y' && path[7] == 's' && path[8] == 't' &&
            path[9] == 'e' && path[10] == 'm' && path[11] == 'd' && path[12] == '/') {
            if (path[13] == 's' && path[14] == 'y' && path[15] == 's' && path[16] == 't' &&
                path[17] == 'e' && path[18] == 'm' && path[19] == '/') {
                return 2;
            }
        }

        // /etc/rc.local
        if (path[5] == 'r' && path[6] == 'c' && path[7] == '.' &&
            path[8] == 'l' && path[9] == 'o' && path[10] == 'c' &&
            path[11] == 'a' && path[12] == 'l' && path[13] == '\0') {
            return 4;
        }

        // /etc/init.d/*
        if (path[5] == 'i' && path[6] == 'n' && path[7] == 'i' && path[8] == 't' &&
            path[9] == '.' && path[10] == 'd' && path[11] == '/') {
            return 4;
        }
    }

    // Check /var/spool/cron/*
    if (path[0] == '/' && path[1] == 'v' && path[2] == 'a' && path[3] == 'r' && path[4] == '/') {
        if (path[5] == 's' && path[6] == 'p' && path[7] == 'o' && path[8] == 'o' && path[9] == 'l' &&
            path[10] == '/' && path[11] == 'c' && path[12] == 'r' && path[13] == 'o' && path[14] == 'n' &&
            path[15] == '/') {
            return 1;
        }
    }

    // Check /usr/lib/systemd/system/*
    if (path[0] == '/' && path[1] == 'u' && path[2] == 's' && path[3] == 'r' && path[4] == '/') {
        if (path[5] == 'l' && path[6] == 'i' && path[7] == 'b' && path[8] == '/' &&
            path[9] == 's' && path[10] == 'y' && path[11] == 's' && path[12] == 't' &&
            path[13] == 'e' && path[14] == 'm' && path[15] == 'd' && path[16] == '/') {
            if (path[17] == 's' && path[18] == 'y' && path[19] == 's' && path[20] == 't' &&
                path[21] == 'e' && path[22] == 'm' && path[23] == '/') {
                return 2;
            }
        }
    }

    // Check shell profiles and autostart (need to look for patterns anywhere in path)
    // Use substring matching for /.bashrc, /.profile, /.bash_profile, /.zshrc, /.config/autostart/
    #pragma unroll
    for (int i = 0; i < 32; i++) {  // Scan first 38 chars - covers /home/username/.bashrc
        if (path[i] == '/' && path[i+1] == '.') {
            // Check .bashrc
            if (path[i+2] == 'b' && path[i+3] == 'a' && path[i+4] == 's' && path[i+5] == 'h' &&
                path[i+6] == 'r' && path[i+7] == 'c' && path[i+8] == '\0') {
                return 3;
            }
            // Check .profile
            if (path[i+2] == 'p' && path[i+3] == 'r' && path[i+4] == 'o' && path[i+5] == 'f' &&
                path[i+6] == 'i' && path[i+7] == 'l' && path[i+8] == 'e' && path[i+9] == '\0') {
                return 3;
            }
            // Check .bash_profile
            if (path[i+2] == 'b' && path[i+3] == 'a' && path[i+4] == 's' && path[i+5] == 'h' &&
                path[i+6] == '_' && path[i+7] == 'p' && path[i+8] == 'r' && path[i+9] == 'o' &&
                path[i+10] == 'f' && path[i+11] == 'i' && path[i+12] == 'l' && path[i+13] == 'e' &&
                path[i+14] == '\0') {
                return 3;
            }
            // Check .zshrc
            if (path[i+2] == 'z' && path[i+3] == 's' && path[i+4] == 'h' && path[i+5] == 'r' &&
                path[i+6] == 'c' && path[i+7] == '\0') {
                return 3;
            }
            // Check .config/autostart/
            if (path[i+2] == 'c' && path[i+3] == 'o' && path[i+4] == 'n' && path[i+5] == 'f' &&
                path[i+6] == 'i' && path[i+7] == 'g' && path[i+8] == '/') {
                if (path[i+9] == 'a' && path[i+10] == 'u' && path[i+11] == 't' && path[i+12] == 'o' &&
                    path[i+13] == 's' && path[i+14] == 't' && path[i+15] == 'a' && path[i+16] == 'r' &&
                    path[i+17] == 't' && path[i+18] == '/') {
                    return 5;
                }
            }
        }
    }

    return 0;  // Not a persistence location
}

// Handler for persistence location monitoring
static __always_inline int handle_persistence_openat(int dfd, const char *pathname, int flags)
{
    char path[MAX_FILENAME_LEN];
    int persist_type;
    __u32 uid;

    if (!pathname)
        return 0;

    // Read path from userspace
    if (bpf_probe_read_user_str(path, sizeof(path), pathname) < 0)
        return 0;

    // Check if this is a persistence location
    persist_type = get_persistence_type(path);
    if (persist_type == 0)
        return 0;  // Not persistence

    // Only interested in WRITE operations (create, modify)
    if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)))
        return 0;

    uid = bpf_get_current_uid_gid();

    // Rate limiting check
    if (should_rate_limit(uid))
        return 0;

    // Reserve event
    struct persistence_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    // Fill event
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->type = EVENT_SECURITY_PERSISTENCE;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memcpy(event->path, path, sizeof(event->path));
    event->flags = flags;
    event->persistence_type = persist_type;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_persistence_openat_tp(struct trace_event_raw_sys_enter *ctx)
{
    int dfd = (int)ctx->args[0];
    const char *pathname = (const char *)ctx->args[1];
    int flags = (int)ctx->args[2];

    return handle_persistence_openat(dfd, pathname, flags);
}

SEC("kprobe/__x64_sys_openat")
int handle_persistence_openat_kp(struct pt_regs *ctx)
{
    int dfd = (int)PT_REGS_PARM1(ctx);
    const char *pathname = (const char *)PT_REGS_PARM2(ctx);
    int flags = (int)PT_REGS_PARM3(ctx);

    return handle_persistence_openat(dfd, pathname, flags);
}

// ============================================================================
// RAW DISK ACCESS DETECTION (T1561.001/002 - Disk Wipe)
// ============================================================================

// Check if path is a raw block device
// Returns true for whole disks, partitions, RAID, LVM, etc.
static __always_inline int is_raw_block_device(const char *path)
{
    // Check for /dev/ prefix (5 chars minimum: /dev/X)
    if (path[0] != '/' || path[1] != 'd' || path[2] != 'e' ||
        path[3] != 'v' || path[4] != '/' || path[5] == '\0') {
        return 0;
    }

    // After /dev/ (index 5)
    char c5 = path[5];

    // Need at least 2 more chars after /dev/ for shortest device names
    if (path[6] == '\0')
        return 0;
    char c6 = path[6];

    if (path[7] == '\0')
        return 0;
    char c7 = path[7];

    // SCSI/SATA disks: /dev/sd[a-z] (whole disk or partitions)
    if (c5 == 's' && c6 == 'd' && c7 >= 'a' && c7 <= 'z') {
        // Validate next char: null (whole disk), digit (partition), or 'p' (nvme-style partition)
        char c8 = path[8];
        if (c8 == '\0' || (c8 >= '0' && c8 <= '9'))
            return 1;
    }

    // NVMe disks: /dev/nvme[0-9]n[0-9] (whole disk or partitions)
    // Need at least 10 chars: /dev/nvme0n1
    if (c5 == 'n' && c6 == 'v' && c7 == 'm') {
        if (path[8] == '\0' || path[9] == '\0')
            return 0;
        if (path[8] == 'e' && path[9] >= '0' && path[9] <= '9') {
            // Check for 'n' separator
            if (path[10] == '\0')
                return 0;
            if (path[10] == 'n' && path[11] >= '0' && path[11] <= '9')
                return 1;
        }
    }

    // Virtio block devices: /dev/vd[a-z]
    if (c5 == 'v' && c6 == 'd' && c7 >= 'a' && c7 <= 'z') {
        char c8 = path[8];
        if (c8 == '\0' || (c8 >= '0' && c8 <= '9'))
            return 1;
    }

    // Xen virtual block devices: /dev/xvd[a-z]
    if (c5 == 'x' && c6 == 'v' && c7 == 'd') {
        if (path[8] == '\0')
            return 0;
        if (path[8] >= 'a' && path[8] <= 'z') {
            char c9 = path[9];
            if (c9 == '\0' || (c9 >= '0' && c9 <= '9'))
                return 1;
        }
    }

    // MMC/SD cards: /dev/mmcblk[0-9]
    // Need at least 12 chars: /dev/mmcblk0
    if (c5 == 'm' && c6 == 'm' && c7 == 'c') {
        if (path[8] == '\0' || path[9] == '\0' || path[10] == '\0' || path[11] == '\0')
            return 0;
        if (path[8] == 'b' && path[9] == 'l' && path[10] == 'k' &&
            path[11] >= '0' && path[11] <= '9') {
            return 1;
        }
    }

    // Software RAID: /dev/md[0-9]
    if (c5 == 'm' && c6 == 'd' && c7 >= '0' && c7 <= '9') {
        return 1;
    }

    // Device mapper (LVM, LUKS): /dev/dm-[0-9]
    if (c5 == 'd' && c6 == 'm' && c7 == '-') {
        if (path[8] == '\0')
            return 0;
        if (path[8] >= '0' && path[8] <= '9')
            return 1;
    }

    // Loop devices: /dev/loop[0-9]
    if (c5 == 'l' && c6 == 'o' && c7 == 'o') {
        if (path[8] == '\0' || path[9] == '\0')
            return 0;
        if (path[8] == 'p' && path[9] >= '0' && path[9] <= '9')
            return 1;
    }

    return 0;  // Not a raw block device
}

// Handler for raw disk access detection
static __always_inline int handle_raw_disk_openat(int dfd, const char *pathname, int flags)
{
    char path[MAX_FILENAME_LEN];
    __u32 uid;

    if (!pathname)
        return 0;

    // Read path from userspace
    if (bpf_probe_read_user_str(path, sizeof(path), pathname) < 0)
        return 0;

    // Check if this is a raw block device
    if (!is_raw_block_device(path))
        return 0;

    // Only interested in WRITE operations (T1561 - Disk Wipe)
    // O_WRONLY or O_RDWR indicate write intent
    if (!(flags & (O_WRONLY | O_RDWR)))
        return 0;

    uid = bpf_get_current_uid_gid();

    // Rate limiting check
    if (should_rate_limit(uid))
        return 0;

    // Reserve event
    struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    // Fill event
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->type = EVENT_RAW_DISK_ACCESS;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memcpy(event->filename, path, sizeof(event->filename));
    event->flags = flags;
    event->target_pid = 0;
    event->port = 0;
    event->family = 0;
    event->extra = 0;

    // Fill process context (ppid, sid, pgid, tty)
    FILL_PROCESS_CONTEXT(event, task);
    FILL_NAMESPACE_INFO(event, task);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_raw_disk_openat_tp(struct trace_event_raw_sys_enter *ctx)
{
    int dfd = (int)ctx->args[0];
    const char *pathname = (const char *)ctx->args[1];
    int flags = (int)ctx->args[2];

    return handle_raw_disk_openat(dfd, pathname, flags);
}

SEC("kprobe/__x64_sys_openat")
int handle_raw_disk_openat_kp(struct pt_regs *ctx)
{
    int dfd = (int)PT_REGS_PARM1(ctx);
    const char *pathname = (const char *)PT_REGS_PARM2(ctx);
    int flags = (int)PT_REGS_PARM3(ctx);

    return handle_raw_disk_openat(dfd, pathname, flags);
}
