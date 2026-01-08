// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// Common definitions shared between eBPF and userspace

#ifndef __LINMON_COMMON_H
#define __LINMON_COMMON_H

#ifdef __BPF__
// BPF code uses kernel types
#include <vmlinux.h>
#else
// Userspace uses Linux kernel types
#include <linux/types.h>
#endif

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_CMDLINE_LEN 512

// File open flags
#define O_WRONLY    00000001
#define O_RDWR      00000002
#define O_CREAT     00000100
#define O_TRUNC     00001000

// Network constants (only for BPF code - userspace uses system headers)
#ifdef __BPF__
#define AF_INET     2
#define AF_INET6    10
#define AF_VSOCK    40
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#endif

// Byte order helpers (for eBPF)
#define __bpf_ntohs(x) __builtin_bswap16(x)

// Init namespace inode numbers (host/non-container processes)
// These values are constant across all Linux systems
#define PROC_PID_INIT_INO  4026531836  // Initial PID namespace
#define PROC_UTS_INIT_INO  4026531838  // Initial UTS namespace
#define PROC_IPC_INIT_INO  4026531839  // Initial IPC namespace
#define PROC_MNT_INIT_INO  4026531840  // Initial mount namespace
#define PROC_NET_INIT_INO  4026531841  // Initial network namespace

// BPF config shared between kernel and userspace
struct bpf_config {
    __u32 min_uid;
    __u32 max_uid;
    __u8 capture_cmdline;
    __u8 require_tty;
    __u8 ignore_threads;  // Only log main processes (pid == tgid)
};

// Network CIDR block for filtering
struct network_cidr {
    __u32 addr;        // Network address (IPv4 only for now)
    __u32 mask;        // Network mask
};

// Event types
enum event_type {
    EVENT_PROCESS_EXEC = 1,
    EVENT_PROCESS_EXIT = 2,
    EVENT_FILE_OPEN = 3,
    EVENT_FILE_CREATE = 4,
    EVENT_FILE_DELETE = 5,
    EVENT_FILE_MODIFY = 6,
    EVENT_NET_CONNECT_TCP = 7,
    EVENT_NET_ACCEPT_TCP = 8,
    EVENT_PRIV_SETUID = 9,
    EVENT_PRIV_SETGID = 10,
    EVENT_PRIV_SUDO = 11,
    EVENT_NET_SEND_UDP = 12,
    EVENT_NET_RECV_UDP = 13,
    EVENT_NET_VSOCK_CONNECT = 23,  // VM/container socket communication
    // Security monitoring events (MITRE ATT&CK detection)
    EVENT_SECURITY_PTRACE = 14,   // T1055 - Process Injection
    EVENT_SECURITY_MODULE = 15,   // T1547.006 - Kernel Module Loading
    EVENT_SECURITY_MEMFD = 16,    // T1620 - Fileless Malware
    EVENT_SECURITY_BIND = 17,     // T1571 - Bind shell / C2 server
    EVENT_SECURITY_UNSHARE = 18,  // T1611 - Container escape / namespace manipulation
    EVENT_SECURITY_EXECVEAT = 19, // T1620 - Fileless execution (fd-based)
    EVENT_SECURITY_BPF = 20,      // T1014 - eBPF rootkit / packet manipulation
    EVENT_SECURITY_CRED_READ = 21,   // T1003.008 - Credential file read (/etc/shadow)
    EVENT_SECURITY_LDPRELOAD = 22,   // T1574.006 - LD_PRELOAD hijacking
    EVENT_SECURITY_PERSISTENCE = 24, // T1053, T1547 - Persistence mechanisms (cron, systemd, shell profiles)
    EVENT_SECURITY_SUID = 25,     // T1548.001 - SUID/SGID manipulation (chmod +s)
    EVENT_SECURITY_CRED_WRITE = 26,  // T1098.001 - Account manipulation (/etc/passwd, shadow, sudoers writes)
    EVENT_SECURITY_LOG_TAMPER = 27,  // T1070.001 - Log file tampering (/var/log/* deletion/truncate)
};

// Process information stored in map
struct process_info {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u64 start_time;
};

// Event structure sent to userspace
struct process_event {
    __u32 type;
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 sid;                    // Session ID (login session)
    __u32 pgid;                   // Process group ID (job control)
    __u32 sudo_uid;               // Original UID before sudo (0 = not via sudo)
    char tty[16];                 // TTY name (e.g., "pts/0") or empty for no TTY
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char cmdline[MAX_CMDLINE_LEN];
    __u32 exit_code;
    // Container/namespace identification
    __u32 pid_ns;                 // PID namespace inode
    __u32 mnt_ns;                 // Mount namespace inode
    __u32 net_ns;                 // Network namespace inode
};

struct file_event {
    __u32 type;
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 sid;
    __u32 pgid;
    char tty[16];
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    __u32 flags;
    __u32 mode;
    // Container/namespace identification
    __u32 pid_ns;
    __u32 mnt_ns;
    __u32 net_ns;
};

struct network_event {
    __u32 type;
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 sid;
    __u32 pgid;
    char tty[16];
    char comm[TASK_COMM_LEN];
    __u8 saddr[16];  // IPv4/IPv6 source address (IPv4 uses first 4 bytes) OR vsock source CID
    __u8 daddr[16];  // IPv4/IPv6 destination address OR vsock destination CID
    __u16 sport;
    __u16 dport;
    __u16 family;    // AF_INET, AF_INET6, or AF_VSOCK
    __u8 protocol;   // TCP, UDP (not used for AF_VSOCK)
    // Container/namespace identification
    __u32 pid_ns;
    __u32 mnt_ns;
    __u32 net_ns;
};

struct privilege_event {
    __u32 type;
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 sid;
    __u32 pgid;
    char tty[16];
    __u32 old_uid;
    __u32 new_uid;
    __u32 old_gid;
    __u32 new_gid;
    char comm[TASK_COMM_LEN];
    char target_comm[TASK_COMM_LEN]; // For sudo: the command being run
    // Container/namespace identification
    __u32 pid_ns;
    __u32 mnt_ns;
    __u32 net_ns;
};

// Security monitoring event (MITRE ATT&CK detection)
struct security_event {
    __u32 type;
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 sid;
    __u32 pgid;
    char tty[16];
    __u32 target_pid;                 // For ptrace: target PID; for execveat: fd
    __u32 flags;                      // ptrace request, module flags, memfd flags, unshare flags
    __u16 port;                       // For bind: port number
    __u16 family;                     // For bind: address family (AF_INET/AF_INET6)
    __u32 extra;                      // For bpf: cmd; for execveat: AT_* flags
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];  // Module name, memfd name, or execveat path
    // Container/namespace identification
    __u32 pid_ns;
    __u32 mnt_ns;
    __u32 net_ns;
};

// Persistence mechanism detection event (T1053, T1547)
struct persistence_event {
    __u32 type;
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 sid;
    __u32 pgid;
    char tty[16];
    char comm[TASK_COMM_LEN];
    char path[MAX_FILENAME_LEN];
    __u32 flags;                      // open() flags
    __u8 persistence_type;            // 1=cron, 2=systemd, 3=shell_profile, 4=init, 5=autostart
    // Container/namespace identification
    __u32 pid_ns;
    __u32 mnt_ns;
    __u32 net_ns;
};

#endif /* __LINMON_COMMON_H */
