# LinMon Example Configurations

This directory contains example configurations optimized for different use cases. Choose the configuration that best matches your environment and security requirements.

## Quick Selection Guide

| Use Case | Configuration | Event Volume | CPU Overhead | Security Level |
|----------|--------------|--------------|--------------|----------------|
| Personal laptop/desktop | `desktop.conf` | 50-200/day | <1% | Medium |
| SSH bastion/jump server | `bastion.conf` | 200-1000/day | 1-3% | High |
| Web/app/database server | `server.conf` | 200-500/day | 0.5-2% | Medium-High |
| Docker/Kubernetes host | `container-host.conf` | 500-2000/day | 2-5% | High |
| Maximum security/forensics | `paranoid.conf` | 5000-50000+/day | 5-20% | Maximum |

## Configuration Descriptions

### desktop.conf - Personal Workstation
**Best for:** Developer laptops, personal desktops, home office systems

**Key features:**
- Monitors only the logged-in user (UID >= 1000)
- Filters browser/IDE thread noise with `ignore_threads = true`
- Disables file monitoring (too noisy for development)
- Network monitoring limited to external connections
- Selective security detections (excludes debuggers, dev tools)

**Event volume:** 50-200 events/day
**Performance:** <1% CPU overhead
**Disk usage:** 5-20MB/day

**When to use:**
- Personal laptops and desktops
- Developer workstations
- Learning/testing LinMon
- Systems where low overhead is critical

**When NOT to use:**
- Production servers (insufficient security monitoring)
- Multi-user systems (only monitors human users)

### bastion.conf - SSH Login Server
**Best for:** SSH bastion hosts, jump servers, privileged access workstations

**Key features:**
- Monitors ALL users including root (UID >= 0)
- Comprehensive credential theft detection
- Network monitoring for lateral movement
- All core security detections enabled
- Frequent integrity checkpoints (15 minutes)
- Extended log retention (30 days)

**Event volume:** 200-1000 events/day
**Performance:** 1-3% CPU overhead
**Disk usage:** 20-100MB/day

**When to use:**
- SSH bastion/jump hosts
- Multi-user login servers
- Privileged access workstations (PAW)
- Systems with elevated security requirements

**SIEM alerts:**
- Alert on `package=null` (unpackaged binaries)
- Alert on `security_cred_read` from unexpected processes
- Alert on TCP connections TO other internal hosts (lateral movement)

### server.conf - Application Server
**Best for:** Web servers, API servers, database servers, general application hosts

**Key features:**
- Monitors all users but with reduced noise
- Thread filtering enabled for multi-threaded apps
- File monitoring disabled (application I/O is noisy)
- Network monitoring for external connections
- Balanced security detections (excludes noisy ones)

**Event volume:** 200-500 events/day
**Performance:** 0.5-2% CPU overhead
**Disk usage:** 20-50MB/day

**When to use:**
- Web application servers (nginx, Apache, Node.js)
- API servers (REST, GraphQL)
- Database servers (MySQL, PostgreSQL, MongoDB)
- Cache servers (Redis, Memcached)
- Message queue servers (RabbitMQ, Kafka)

**Tuning tips:**
- Add noisy applications to `ignore_processes`
- Adjust `ignore_networks` based on infrastructure
- Monitor for 1 week, analyze volume, adjust filters

### container-host.conf - Container Orchestration
**Best for:** Docker hosts, Kubernetes nodes, container platforms

**Key features:**
- Container metadata capture enabled (`capture_container_metadata = true`)
- vsock monitoring for VM-to-host communication
- Namespace manipulation detection (`monitor_unshare = true`)
- Minimal network filtering (containers use private networks)
- Larger log rotation (200MB files)

**Event volume:** 500-2000 events/day
**Performance:** 2-5% CPU overhead
**Disk usage:** 50-200MB/day

**When to use:**
- Docker hosts running multiple containers
- Kubernetes worker nodes
- Container orchestration platforms (OpenShift, Rancher)
- Microservices infrastructure

**Container escape detection:**
- Monitor `security_unshare` events (namespace manipulation)
- Track namespace inode changes (`container.ns_pid` field)
- Alert on container processes accessing host filesystem

**SIEM integration:**
- Group events by `container.id` for per-container analysis
- Alert on `container.runtime=unknown`
- Correlate `container.pod_id` for Kubernetes pod-level tracking
- Baseline normal container behavior per image hash

### paranoid.conf - Maximum Security
**Best for:** Incident response, forensic analysis, high-security environments

**WARNING:** Generates VERY HIGH event volume (5,000-50,000+ events/day)

**Key features:**
- ALL monitoring enabled (processes, files, network, UDP, vsock)
- NO filtering (all users, all processes, all networks)
- ALL security detections enabled
- Logs process exit events (complete audit trail)
- Very frequent integrity checkpoints (5 minutes)
- Massive log retention (500MB files, 50 rotations)

**Event volume:** 5,000-50,000+ events/day
**Performance:** 5-20% CPU overhead
**Disk usage:** 500MB-5GB/day

**When to use:**
- Active incident response (24-72 hour deployment)
- Forensic analysis and evidence collection
- High-value targets (finance, defense, healthcare)
- Security research and honeypots
- Compliance requirements (PCI-DSS, HIPAA strict mode)

**Infrastructure requirements:**
- Fast disk I/O (SSD recommended)
- SIEM capable of 50-500 events/second ingestion
- Sufficient CPU and memory resources
- Large disk space for log retention

**When NOT to use:**
- Long-term continuous monitoring (cost prohibitive)
- Production servers (performance impact)
- Resource-constrained systems

## Installation

1. Choose the appropriate configuration for your use case
2. Copy to `/etc/linmon/linmon.conf`:
   ```bash
   sudo cp examples/configs/server.conf /etc/linmon/linmon.conf
   ```
3. Adjust any host-specific values (paths, UIDs, network ranges)
4. Reload LinMon:
   ```bash
   sudo systemctl reload linmond
   ```

## Customization

All configurations can be customized. Common adjustments:

### UID Filtering
```ini
# Desktop: Only monitor human users
min_uid = 1000

# Server: Monitor all users including root
min_uid = 0
```

### Network Filtering
```ini
# Filter all private networks (bastion hosts: DON'T do this)
ignore_networks = 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

# Only filter localhost (maximum visibility)
ignore_networks = 127.0.0.0/8
```

### Process Filtering
```ini
# Reduce noise from known applications
ignore_processes = chrome,firefox,slack,vscode

# Or focus on specific processes only
only_processes = ssh,sudo,bash
```

### Security Monitoring
```ini
# Enable/disable specific detections based on environment
monitor_ptrace = false     # Disable if using debuggers (gdb, strace)
monitor_bind = false       # Disable if applications bind ports legitimately
monitor_persistence = true # Enable for high-security environments
```

## Testing Your Configuration

After applying a new configuration:

1. Monitor event volume:
   ```bash
   sudo journalctl -u linmond -f
   sudo tail -f /var/log/linmon/events.json | wc -l
   ```

2. Check for errors:
   ```bash
   sudo systemctl status linmond
   ```

3. Analyze event distribution:
   ```bash
   sudo cat /var/log/linmon/events.json | jq -r '.type' | sort | uniq -c | sort -rn
   ```

4. Verify expected events are logged:
   ```bash
   # Test process monitoring
   echo "test" > /tmp/test.txt

   # Check logs
   sudo tail /var/log/linmon/events.json | jq 'select(.comm == "bash")'
   ```

## Tuning for Your Environment

Start with the recommended configuration and tune over 1-2 weeks:

1. **Week 1:** Run with default config, measure baseline event volume
2. **Week 2:** Adjust filters based on observed noise
3. **Ongoing:** Monitor SIEM alerts, refine detection rules

### Common Tuning Scenarios

**Too many events?**
- Enable `ignore_threads = true`
- Add noisy processes to `ignore_processes`
- Disable `monitor_files` or add paths to `ignore_file_paths`
- Increase `min_uid` to filter system services

**Missing important events?**
- Disable `require_tty` to capture non-interactive sessions
- Remove entries from `ignore_processes`
- Reduce network filtering in `ignore_networks`
- Enable additional security monitors

**Performance issues?**
- Disable `monitor_files` (highest overhead)
- Enable `ignore_threads = true`
- Increase `min_uid` to reduce monitoring scope
- Add high-exec-rate processes to `ignore_processes`

## Support

- Documentation: See main LinMon `README.md` and `MONITORING.md`
- Issues: https://github.com/espegro/linmon/issues
- Security: See `SECURITY.md` for MITRE ATT&CK mapping
