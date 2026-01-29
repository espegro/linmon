-- ClickHouse schema for LinMon events
-- ClickHouse is a columnar OLAP database optimized for analytics queries
--
-- Installation:
--   Ubuntu: sudo apt-get install clickhouse-server clickhouse-client
--   RHEL:   sudo yum install clickhouse-server clickhouse-client
--
-- Usage:
--   clickhouse-client < extras/clickhouse/schema.sql
--
-- Documentation: https://clickhouse.com/docs

-- Create database
CREATE DATABASE IF NOT EXISTS linmon;

-- Create main events table with MergeTree engine (optimized for time-series data)
CREATE TABLE IF NOT EXISTS linmon.events
(
    -- Common fields (all events)
    seq Nullable(UInt64),                                    -- v1.3.0: Event sequence number (tamper detection)
    timestamp DateTime64(3, 'UTC'),
    ingest_timestamp DateTime64(3, 'UTC') DEFAULT now64(3),
    hostname LowCardinality(String),
    type LowCardinality(String),
    event_category LowCardinality(String),
    mitre_technique LowCardinality(Nullable(String)),

    -- Process identifiers
    pid Nullable(UInt32),
    ppid Nullable(UInt32),
    sid Nullable(UInt32),
    pgid Nullable(UInt32),
    uid Nullable(UInt32),
    username LowCardinality(Nullable(String)),

    -- Sudo tracking (v1.3.0)
    sudo_uid Nullable(UInt32),
    sudo_user LowCardinality(Nullable(String)),

    -- Process details
    comm LowCardinality(Nullable(String)),
    process_name LowCardinality(Nullable(String)),           -- v1.3.2: Basename of executable
    filename Nullable(String),
    cmdline Nullable(String),
    tty LowCardinality(Nullable(String)),

    -- Process security flags (v1.3.3)
    comm_mismatch Nullable(UInt8),                           -- Process masquerading detection
    deleted_executable Nullable(UInt8),                      -- Fileless execution detection

    -- Binary verification (process_exec events)
    sha256 Nullable(FixedString(64)),
    package LowCardinality(Nullable(String)),
    pkg_modified Nullable(UInt8),

    -- Process exit (process_exit events)
    exit_code Nullable(Int32),

    -- File events
    flags Nullable(UInt32),

    -- Network events
    saddr Nullable(IPv6),
    daddr Nullable(IPv6),
    sport Nullable(UInt16),
    dport Nullable(UInt16),

    -- Privilege events
    old_uid Nullable(UInt32),
    new_uid Nullable(UInt32),
    old_gid Nullable(UInt32),
    new_gid Nullable(UInt32),
    old_username LowCardinality(Nullable(String)),
    new_username LowCardinality(Nullable(String)),
    target_comm LowCardinality(Nullable(String)),

    -- Security events (specific to event type)
    target_pid Nullable(UInt32),
    ptrace_request Nullable(UInt32),
    module_flags Nullable(UInt32),
    memfd_name Nullable(String),
    memfd_flags Nullable(UInt32),
    port Nullable(UInt16),
    family Nullable(UInt32),
    fd Nullable(UInt32),
    unshare_flags Nullable(UInt32),
    dirfd Nullable(Int32),
    at_flags Nullable(UInt32),
    pathname Nullable(String),
    bpf_cmd Nullable(UInt32),
    cred_file LowCardinality(Nullable(String)),
    open_flags Nullable(UInt32),
    path Nullable(String),

    -- v1.4.0/v1.4.1 additions
    persistence_type LowCardinality(Nullable(String)),  -- cron, systemd, shell_profile, init, autostart
    tamper_type LowCardinality(Nullable(String)),       -- truncate, delete
    suid Nullable(UInt8),                                -- SUID bit set
    sgid Nullable(UInt8),                                -- SGID bit set
    mode Nullable(UInt32),                               -- Full file mode for SUID events

    -- v1.5.0: Container metadata (sparse - only for containerized processes)
    container_runtime LowCardinality(Nullable(String)),  -- docker, podman, kubernetes, containerd, lxc, systemd-nspawn
    container_id LowCardinality(Nullable(String)),       -- Full container ID or name
    container_pod_id LowCardinality(Nullable(String)),   -- Kubernetes pod UUID
    container_ns_pid Nullable(UInt32),                   -- PID namespace inode
    container_ns_mnt Nullable(UInt32),                   -- Mount namespace inode
    container_ns_net Nullable(UInt32),                   -- Network namespace inode

    -- v1.7.1: Authentication integrity monitoring (T1556.003/T1556.004)
    auth_file_path Nullable(String),                     -- Path to monitored authentication file
    auth_verdict LowCardinality(Nullable(String)),       -- not_in_package_database, modified_after_install, hash_mismatch
    auth_modified Nullable(UInt8)                        -- Package modification flag
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (hostname, type, timestamp, pid)
TTL timestamp + INTERVAL 90 DAY  -- Auto-delete events older than 90 days
SETTINGS index_granularity = 8192;

-- Create materialized view for fast process execution queries
CREATE MATERIALIZED VIEW IF NOT EXISTS linmon.process_exec_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (hostname, comm, toStartOfHour(timestamp))
AS SELECT
    hostname,
    comm,
    toStartOfHour(timestamp) as hour,
    count() as exec_count,
    uniqExact(uid) as unique_users,
    uniqExact(filename) as unique_binaries
FROM linmon.events
WHERE type = 'process_exec'
GROUP BY hostname, comm, hour;

-- Create materialized view for network connection statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS linmon.network_stats_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (hostname, type, toStartOfHour(timestamp))
AS SELECT
    hostname,
    type,
    toStartOfHour(timestamp) as hour,
    count() as connection_count,
    uniqExact(daddr) as unique_destinations,
    uniqExact(dport) as unique_ports
FROM linmon.events
WHERE type IN ('net_connect_tcp', 'net_accept_tcp', 'net_send_udp')
GROUP BY hostname, type, hour;

-- Create materialized view for security event alerts
CREATE MATERIALIZED VIEW IF NOT EXISTS linmon.security_alerts_mv
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (hostname, mitre_technique, timestamp)
AS SELECT
    timestamp,
    hostname,
    type,
    mitre_technique,
    pid,
    uid,
    username,
    comm,
    filename,
    target_pid,
    memfd_name,
    cred_file
FROM linmon.events
WHERE event_category = 'security';

-- ==============================================================================
-- Example Queries
-- ==============================================================================

-- Top 10 most executed commands in last 24 hours
-- SELECT
--     comm,
--     count() as executions,
--     uniqExact(uid) as unique_users
-- FROM linmon.events
-- WHERE type = 'process_exec' AND timestamp > now() - INTERVAL 24 HOUR
-- GROUP BY comm
-- ORDER BY executions DESC
-- LIMIT 10;

-- Find all sudo usage by user
-- SELECT
--     timestamp,
--     old_username,
--     new_username,
--     target_comm,
--     hostname
-- FROM linmon.events
-- WHERE type = 'priv_sudo'
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- Detect suspicious network connections (non-standard ports)
-- SELECT
--     timestamp,
--     hostname,
--     comm,
--     IPv6NumToString(daddr) as destination,
--     dport,
--     username
-- FROM linmon.events
-- WHERE type = 'net_connect_tcp'
--   AND dport NOT IN (22, 80, 443, 53)
--   AND timestamp > now() - INTERVAL 1 HOUR
-- ORDER BY timestamp DESC;

-- MITRE ATT&CK technique frequency
-- SELECT
--     mitre_technique,
--     type,
--     count() as occurrences,
--     uniqExact(hostname) as affected_hosts,
--     min(timestamp) as first_seen,
--     max(timestamp) as last_seen
-- FROM linmon.events
-- WHERE mitre_technique IS NOT NULL
-- GROUP BY mitre_technique, type
-- ORDER BY occurrences DESC;

-- Find binaries not from packages (potential malware)
-- SELECT
--     timestamp,
--     hostname,
--     filename,
--     sha256,
--     username,
--     cmdline
-- FROM linmon.events
-- WHERE type = 'process_exec'
--   AND package IS NULL
--   AND filename NOT LIKE '/tmp/%'
--   AND filename NOT LIKE '/home/%'
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- Process execution timeline for a specific user
-- SELECT
--     timestamp,
--     hostname,
--     comm,
--     filename,
--     cmdline,
--     ppid
-- FROM linmon.events
-- WHERE type = 'process_exec'
--   AND username = 'alice'
--   AND timestamp > now() - INTERVAL 1 DAY
-- ORDER BY timestamp DESC;

-- Detect credential file READ access (T1003.008, T1552.004)
-- SELECT
--     timestamp,
--     hostname,
--     comm,
--     username,
--     cred_file,
--     path,
--     open_flags
-- FROM linmon.events
-- WHERE type = 'security_cred_read'
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- Detect credential file WRITE access (T1098.001, T1098.004)
-- SELECT
--     timestamp,
--     hostname,
--     comm,
--     username,
--     cred_file,
--     path,
--     open_flags
-- FROM linmon.events
-- WHERE type = 'security_cred_write'
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- Detect log tampering (T1070.001)
-- SELECT
--     timestamp,
--     hostname,
--     comm,
--     username,
--     tamper_type,
--     path
-- FROM linmon.events
-- WHERE type = 'security_log_tamper'
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- Detect persistence mechanisms (T1053, T1547)
-- SELECT
--     timestamp,
--     hostname,
--     comm,
--     username,
--     persistence_type,
--     path
-- FROM linmon.events
-- WHERE type = 'security_persistence'
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- Detect SUID/SGID manipulation (T1548.001)
-- SELECT
--     timestamp,
--     hostname,
--     comm,
--     username,
--     path,
--     suid,
--     sgid,
--     mode
-- FROM linmon.events
-- WHERE type = 'security_suid'
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- Network connections per host (hourly aggregation)
-- SELECT
--     toStartOfHour(timestamp) as hour,
--     hostname,
--     type,
--     count() as connection_count
-- FROM linmon.events
-- WHERE type IN ('net_connect_tcp', 'net_accept_tcp')
--   AND timestamp > now() - INTERVAL 7 DAY
-- GROUP BY hour, hostname, type
-- ORDER BY hour DESC, connection_count DESC;

-- ==============================================================================
-- v1.5.0+ Queries: Container Security
-- ==============================================================================

-- Find processes running in containers
-- SELECT
--     timestamp,
--     hostname,
--     container_runtime,
--     container_id,
--     comm,
--     username,
--     cmdline
-- FROM linmon.events
-- WHERE container_runtime IS NOT NULL
--   AND timestamp > now() - INTERVAL 1 DAY
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- Detect container escape attempts (namespace changes)
-- SELECT
--     timestamp,
--     hostname,
--     comm,
--     username,
--     container_runtime,
--     container_ns_pid,
--     container_ns_mnt,
--     container_ns_net
-- FROM linmon.events
-- WHERE type = 'security_unshare'
--   AND container_runtime IS NOT NULL
-- ORDER BY timestamp DESC;

-- Container activity by runtime
-- SELECT
--     container_runtime,
--     count() as event_count,
--     uniqExact(container_id) as unique_containers,
--     uniqExact(comm) as unique_processes
-- FROM linmon.events
-- WHERE container_runtime IS NOT NULL
--   AND timestamp > now() - INTERVAL 7 DAY
-- GROUP BY container_runtime
-- ORDER BY event_count DESC;

-- ==============================================================================
-- v1.3.0+ Queries: Sudo Tracking & Event Sequence
-- ==============================================================================

-- Find sudo privilege escalations
-- SELECT
--     timestamp,
--     hostname,
--     username,
--     sudo_user,
--     comm,
--     cmdline
-- FROM linmon.events
-- WHERE sudo_uid IS NOT NULL
--   AND timestamp > now() - INTERVAL 1 DAY
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- Detect event sequence gaps (tamper detection)
-- SELECT
--     hostname,
--     type,
--     seq,
--     seq - lagInFrame(seq, 1) OVER (PARTITION BY hostname ORDER BY seq) as seq_gap
-- FROM linmon.events
-- WHERE timestamp > now() - INTERVAL 1 HOUR
-- HAVING seq_gap > 1
-- ORDER BY seq DESC;

-- ==============================================================================
-- v1.3.3+ Queries: Process Masquerading & Fileless Execution
-- ==============================================================================

-- Detect process masquerading (comm mismatch)
-- SELECT
--     timestamp,
--     hostname,
--     comm,
--     process_name,
--     filename,
--     username,
--     cmdline
-- FROM linmon.events
-- WHERE comm_mismatch = 1
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- Detect fileless execution (deleted binaries)
-- SELECT
--     timestamp,
--     hostname,
--     comm,
--     filename,
--     username,
--     sha256
-- FROM linmon.events
-- WHERE deleted_executable = 1
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- ==============================================================================
-- v1.7.1+ Queries: Authentication Integrity Monitoring
-- ==============================================================================

-- Authentication file integrity violations (T1556.003/T1556.004)
-- SELECT
--     timestamp,
--     hostname,
--     auth_file_path,
--     auth_verdict,
--     package,
--     auth_modified,
--     sha256
-- FROM linmon.events
-- WHERE type = 'auth_integrity_violation'
-- ORDER BY timestamp DESC
-- LIMIT 100;

-- Summary of authentication violations by file
-- SELECT
--     auth_file_path,
--     auth_verdict,
--     count() as violation_count,
--     max(timestamp) as last_seen
-- FROM linmon.events
-- WHERE type = 'auth_integrity_violation'
--   AND timestamp > now() - INTERVAL 7 DAY
-- GROUP BY auth_file_path, auth_verdict
-- ORDER BY violation_count DESC;
