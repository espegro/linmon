# Filebeat Configurations for LinMon

This directory contains two Filebeat configurations for shipping LinMon events to Elasticsearch:

## Configuration Files

### 1. `filebeat.yml` - Standard Configuration
**Use when:**
- You want simple, flat JSON structure
- You're using non-Elastic SIEM (Splunk, custom, etc.)
- You want minimal transformation overhead
- You don't need Elastic Security features

**Format example:**
```json
{
  "@timestamp": "2025-12-28T22:10:10.123Z",
  "type": "process_exec",
  "seq": 1234,
  "hostname": "marge",
  "pid": 1234,
  "ppid": 1000,
  "uid": 1000,
  "username": "alice",
  "comm": "bash",
  "cmdline": "/bin/bash"
}
```

**Features:**
- Flat JSON structure (same as LinMon output)
- Adds event.category based on type
- Adds MITRE ATT&CK technique IDs
- Lightweight processing

---

### 2. `filebeat-ecs.yml` - ECS (Elastic Common Schema) Configuration ⭐ **Recommended**
**Use when:**
- You're using Elasticsearch + Kibana
- You want Elastic Security integration
- You want pre-built dashboards and visualizations
- You need standardized field names for correlation

**Format example:**
```json
{
  "@timestamp": "2025-12-28T22:10:10.123Z",
  "event": {
    "action": "process_exec",
    "category": ["process"],
    "type": ["start", "process_start"],
    "kind": "event",
    "sequence": 1234
  },
  "host": {
    "hostname": "marge",
    "name": "marge"
  },
  "process": {
    "pid": 1234,
    "parent": {"pid": 1000},
    "name": "bash",
    "command_line": "/bin/bash",
    "executable": "/bin/bash"
  },
  "user": {
    "id": "1000",
    "name": "alice"
  },
  "linmon": {
    "type": "process_exec",
    "seq": 1234,
    "pid": 1234,
    "ppid": 1000,
    "uid": 1000,
    "username": "alice",
    "comm": "bash"
  }
}
```

**Features:**
- Full ECS compliance (nested objects)
- Preserves original LinMon fields under `linmon.*` namespace
- Maps all fields to ECS equivalents:
  - Process: `process.pid`, `process.parent.pid`, `process.command_line`, etc.
  - User: `user.id`, `user.name`, `user.effective.id` (sudo)
  - Network: `source.ip`, `destination.ip`, `network.transport`
  - Security: `threat.technique.id`, `threat.tactic.name`
- Works with Elastic Security rules and dashboards
- Enables correlation with other ECS data sources

---

## Installation

### For Standard Configuration:
```bash
sudo cp extras/filebeat/filebeat.yml /etc/filebeat/filebeat.yml
sudo systemctl restart filebeat
```

### For ECS Configuration (Recommended):
```bash
sudo cp extras/filebeat/filebeat-ecs.yml /etc/filebeat/filebeat.yml
sudo systemctl restart filebeat
```

---

## ECS Field Mapping

| LinMon Field | ECS Field | Description |
|--------------|-----------|-------------|
| `timestamp` | `@timestamp` | Event timestamp |
| `type` | `event.action` | LinMon event type |
| `seq` | `event.sequence` | Event sequence number (tamper detection) |
| `hostname` | `host.hostname`, `host.name` | System hostname |
| **Process** |
| `pid` | `process.pid` | Process ID |
| `ppid` | `process.parent.pid` | Parent process ID |
| `sid` | `process.session_leader.pid` | Session leader PID |
| `pgid` | `process.group_leader.pid` | Process group leader PID |
| `comm` | `process.name` | Process name (16-char kernel limit) |
| `process_name` | `process.executable` | Full executable name |
| `filename` | `process.executable`, `file.path` | Full path to executable |
| `cmdline` | `process.command_line` | Command line arguments |
| `sha256` | `process.hash.sha256` | Binary SHA256 hash |
| `package` | `package.name`, `process.code_signature.subject_name` | Package name |
| `pkg_modified` | `process.code_signature.valid` | Package integrity (true = valid) |
| `tty` | `process.interactive` | Whether process has TTY |
| **User** |
| `uid` | `user.id` | User ID |
| `username` | `user.name` | Username |
| `gid` | `user.group.id` | Group ID |
| `sudo_uid` | `user.effective.id` | Sudo original UID |
| `sudo_user` | `user.effective.name` | Sudo original username |
| **Network** |
| `saddr` | `source.ip` | Source IP address |
| `daddr` | `destination.ip` | Destination IP address |
| `sport` | `source.port` | Source port |
| `dport` | `destination.port` | Destination port |
| `family` | `network.type` | IP family (ipv4/ipv6/vsock) |
| `protocol` | `network.transport` | Protocol (tcp/udp) |
| **File** |
| `path` | `file.path` | File path |
| `inode` | `file.inode` | File inode |
| **Security** |
| MITRE mapping | `threat.framework` | "MITRE ATT&CK" |
| MITRE mapping | `threat.technique.id` | Technique ID (e.g., "T1055") |
| MITRE mapping | `threat.technique.name` | Technique name (e.g., "Process Injection") |
| MITRE mapping | `threat.tactic.name` | Tactic name (e.g., "Defense Evasion") |

---

## Event Category Mapping

LinMon events are mapped to ECS categories:

| LinMon Type Prefix | ECS Category | ECS Type | ECS Kind |
|-------------------|--------------|----------|----------|
| `process_exec` | `process` | `start`, `process_start` | `event` |
| `process_exit` | `process` | `end`, `process_end` | `event` |
| `file_create` | `file` | `creation` | `event` |
| `file_modify` | `file` | `change` | `event` |
| `file_delete` | `file` | `deletion` | `event` |
| `net_connect_*` | `network` | `connection`, `start` | `event` |
| `net_accept_*` | `network` | `connection`, `start` | `event` |
| `net_send_*` | `network` | `protocol` | `event` |
| `priv_*` | `authentication`, `iam` | `change` | `event` |
| `security_*` | `intrusion_detection`, `malware` | `indicator` | `alert` |

---

## MITRE ATT&CK Mapping

Security events include MITRE ATT&CK context:

| LinMon Event | Technique ID | Technique Name | Tactic |
|--------------|--------------|----------------|--------|
| `security_ptrace` | T1055 | Process Injection | Defense Evasion |
| `security_module_load` | T1547.006 | Kernel Modules and Extensions | Persistence |
| `security_memfd_create` | T1620 | Reflective Code Loading | Defense Evasion |
| `security_execveat` | T1620 | Reflective Code Loading | Defense Evasion |
| `security_bind` | T1571 | Non-Standard Port | Command and Control |
| `security_unshare` | T1611 | Escape to Host | Privilege Escalation |
| `security_bpf` | T1014 | Rootkit | Defense Evasion |
| `security_cred_read` | T1003.008 | OS Credential Dumping | Credential Access |
| `security_ldpreload` | T1574.006 | Dynamic Linker Hijacking | Persistence |

---

## Elasticsearch Integration

### Index Lifecycle Management (ILM)

The ECS configuration uses ILM for automatic index rollover:

```yaml
ilm.enabled: true
ilm.rollover_alias: "linmon-ecs"
ilm.pattern: "{now/d}-000001"
```

This creates daily indices: `linmon-ecs-2025.12.28-000001`, etc.

### Index Template

Elasticsearch will auto-create an index template. For custom mappings, see the example at the end of `filebeat-ecs.yml`.

### Kibana Dashboards

With ECS format, you can use:
- **Elastic Security** app → Events → All events
- **Kibana Discover** with ECS field filters
- Pre-built visualizations for process trees, network connections, etc.

---

## Example Queries

### Kibana Query Language (KQL)

**Find all processes started by user "alice":**
```kql
event.action: "process_exec" AND user.name: "alice"
```

**Find suspicious network connections:**
```kql
event.category: "network" AND NOT destination.ip: (127.0.0.1 OR 10.0.0.0/8 OR 192.168.0.0/16)
```

**Find MITRE ATT&CK T1055 (Process Injection):**
```kql
threat.technique.id: "T1055"
```

**Find package-modified binaries:**
```kql
process.code_signature.valid: false
```

**Find sudo escalations:**
```kql
user.effective.id: * AND user.effective.name: *
```

### Elasticsearch DSL

**Aggregate processes by user:**
```json
GET linmon-ecs-*/_search
{
  "size": 0,
  "aggs": {
    "by_user": {
      "terms": { "field": "user.name" },
      "aggs": {
        "by_process": {
          "terms": { "field": "process.name" }
        }
      }
    }
  }
}
```

---

## Performance Comparison

| Configuration | Processing Overhead | Storage Size | Query Performance | Kibana Integration |
|---------------|---------------------|--------------|-------------------|-------------------|
| `filebeat.yml` | Low (minimal transformation) | Small (flat structure) | Fast | Manual dashboards |
| `filebeat-ecs.yml` | Medium (ECS mapping) | Larger (nested objects) | Optimized for ECS | Pre-built dashboards |

**Recommendation:** Use ECS configuration unless you have specific constraints.

---

## Troubleshooting

### Check Filebeat logs:
```bash
sudo journalctl -u filebeat -f
```

### Test configuration:
```bash
sudo filebeat test config -c /etc/filebeat/filebeat.yml
sudo filebeat test output -c /etc/filebeat/filebeat.yml
```

### Verify ECS transformation:
```bash
# Check Elasticsearch for ECS fields
curl -u elastic:password http://localhost:9200/linmon-ecs-*/_search?size=1 | jq .
```

### Common issues:

**JavaScript processor not enabled:**
```
Error: javascript processor not enabled
```
Solution: Filebeat 7.x+ has JavaScript enabled by default. For older versions, rebuild with `-tags=javascript`.

**Missing @timestamp:**
```
Failed to parse timestamp
```
Solution: Ensure LinMon is running and `timestamp` field exists in events.

---

## See Also

- [Elastic Common Schema (ECS) Reference](https://www.elastic.co/guide/en/ecs/current/index.html)
- [Filebeat Documentation](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)
- [Elastic Security Documentation](https://www.elastic.co/guide/en/security/current/index.html)
- [LinMon MONITORING.md](../../MONITORING.md) for query examples
