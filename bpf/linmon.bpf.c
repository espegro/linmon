// SPDX-License-Identifier: GPL-2.0
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
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
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
// - Allow burst of up to 20 events
// - Refill at 100 events/second (1 token per 10ms)
// - This allows normal activity spikes while preventing flooding
#define RATE_LIMIT_MAX_TOKENS 20
#define RATE_LIMIT_REFILL_INTERVAL_NS 10000000ULL  // 10ms = 100 events/sec

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
    bpf_map_update_elem(&rate_limit_map, &uid, state, BPF_EXIST);
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

// Helper function for openat monitoring (shared between tracepoint and kprobe)
static __always_inline int handle_openat_common(const char *filename, int flags)
{
    __u32 uid = bpf_get_current_uid_gid();
    struct file_event *event;

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

    event->type = (flags & O_CREAT) ? EVENT_FILE_CREATE : EVENT_FILE_MODIFY;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;
    event->flags = flags;

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
    struct file_event *event;

    if (!should_monitor_uid(uid))
        return 0;

    if (should_rate_limit(uid))
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = EVENT_FILE_DELETE;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;
    event->flags = 0;

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

    event->type = EVENT_NET_CONNECT_TCP;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

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

    event->type = EVENT_NET_CONNECT_TCP;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

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

    event->type = EVENT_NET_ACCEPT_TCP;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

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

    event->type = EVENT_NET_SEND_UDP;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

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

    event->type = EVENT_NET_SEND_UDP;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = uid;

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
// PRIVILEGE ESCALATION MONITORING
// ============================================================================

SEC("tp/sched/sched_process_exec")
int handle_privilege_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct privilege_event *event;
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

    event->type = EVENT_PRIV_SUDO;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->old_uid = uid_gid & 0xFFFFFFFF;
    event->old_gid = uid_gid >> 32;
    event->new_uid = 0;  // Will be set if/when setuid is called
    event->new_gid = 0;

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

    event->type = EVENT_PRIV_SETUID;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->old_uid = old_uid;
    event->new_uid = new_uid;
    event->old_gid = uid_gid >> 32;
    event->new_gid = uid_gid >> 32;

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

    event->type = EVENT_PRIV_SETGID;
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->old_uid = uid_gid & 0xFFFFFFFF;
    event->new_uid = uid_gid & 0xFFFFFFFF;
    event->old_gid = old_gid;
    event->new_gid = new_gid;

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
