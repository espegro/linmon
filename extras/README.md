# LinMon Integration Examples

This directory contains configuration examples for integrating LinMon with various SIEM, log aggregation, and analytics platforms.

## Directory Structure

```
extras/
├── RISK_ANALYSIS.md     # Security risk analysis and threat modeling
├── rsyslog-remote.conf  # Remote syslog forwarding (tamper-resistant logs)
├── vector/              # Vector.dev configuration (recommended)
├── clickhouse/          # ClickHouse schema and queries
├── filebeat/            # Filebeat configuration for ELK stack
├── reports/             # Daily and security reporting scripts
└── splunk/              # Splunk configurations (coming soon)
```

## Risk Analysis & Threat Modeling

**Best for**: Security teams, compliance audits, risk assessments

See **[RISK_ANALYSIS.md](RISK_ANALYSIS.md)** for comprehensive analysis of:
- **Why** organizations need runtime monitoring (threat landscape, compliance)
- **What risks** LinMon mitigates (MITRE ATT&CK coverage, incident response)
- **What risks** LinMon introduces (privileged access, kernel access, performance)
- **How** those risks are mitigated (privilege dropping, BPF verifier, tamper detection)
- **What remains** as residual risk (root attackers, zero-days, evasion)

Key topics:
- Business case for deployment (dwell time reduction: 287 days → 24 days)
- MITRE ATT&CK technique coverage (13 techniques directly detected)
- Attack surface analysis and defense-in-depth recommendations
- Compliance mapping (PCI-DSS, NIST CSF, HIPAA, SOC 2)
- Incident response integration workflows
- Risk acceptance matrix with severity/likelihood analysis

## Remote Syslog Forwarding (Tamper Detection)

**Best for**: Tamper-resistant audit trails, compliance, security monitoring

LinMon logs daemon lifecycle events and periodic integrity checkpoints to syslog/journald. Forward these to a remote syslog server for tamper-resistant logging:

```bash
# Copy the example configuration
sudo cp extras/rsyslog-remote.conf /etc/rsyslog.d/10-linmon-remote.conf

# Edit to set your remote syslog server
sudo vi /etc/rsyslog.d/10-linmon-remote.conf
# Replace: @@remote-syslog-server.example.com:514
# With your actual server and port

# Restart rsyslog
sudo systemctl restart rsyslog
```

**What gets forwarded:**
- **Daemon lifecycle**: startup, reload (SIGHUP), shutdown with signal sender info
- **Periodic checkpoints**: Every 30 min with sequence numbers, event counts, SHA256 hashes
- **Integrity monitoring**: Daemon binary hash, config file hash (detects tampering)

**Why remote syslog?**
- Attacker who compromises host cannot delete remote logs
- Sequence numbers detect deleted events (gaps indicate tampering)
- Integrity hashes detect binary/config replacement
- Provides independent audit trail for forensics

See **[rsyslog-remote.conf](rsyslog-remote.conf)** for:
- Complete configuration examples (TCP, UDP, TLS)
- Tamper detection strategies and example queries
- Security hardening recommendations

## Quick Start

### Option 1: Vector.dev + ClickHouse (Recommended)

**Best for**: High-volume environments, analytics, long-term storage

1. Install Vector.dev:
   ```bash
   curl -sSfL https://sh.vector.dev | bash -s -- -y
   ```

2. Install ClickHouse:
   ```bash
   # Ubuntu
   sudo apt-get install clickhouse-server clickhouse-client

   # RHEL
   sudo yum install clickhouse-server clickhouse-client
   ```

3. Create ClickHouse schema:
   ```bash
   clickhouse-client < extras/clickhouse/schema.sql
   ```

4. Start Vector:
   ```bash
   vector --config extras/vector/vector.toml
   ```

5. Query events:
   ```bash
   clickhouse-client
   SELECT * FROM linmon.events LIMIT 10;
   ```

**Why ClickHouse?**
- Columnar storage optimized for analytics queries
- 100-1000x faster than traditional databases for analytical workloads
- Built-in compression (10-40x reduction)
- Materialized views for real-time aggregations
- TTL support for automatic data retention

### Option 2: Filebeat + Elasticsearch (ELK Stack)

**Best for**: Existing ELK infrastructure, full-text search

1. Install Filebeat:
   ```bash
   # Ubuntu
   sudo apt-get install filebeat

   # RHEL
   sudo yum install filebeat
   ```

2. Copy configuration:
   ```bash
   sudo cp extras/filebeat/filebeat.yml /etc/filebeat/filebeat.yml
   ```

3. Edit configuration:
   ```bash
   sudo vi /etc/filebeat/filebeat.yml
   # Set ELASTICSEARCH_PASSWORD environment variable or edit password field
   ```

4. Start Filebeat:
   ```bash
   sudo systemctl enable filebeat
   sudo systemctl start filebeat
   ```

5. Verify in Elasticsearch:
   ```bash
   curl -u elastic:password http://localhost:9200/linmon-*/_search?size=10
   ```

### Option 3: Vector.dev + Elasticsearch

**Best for**: High performance + Elasticsearch

Vector.dev can also send to Elasticsearch (uncomment the elasticsearch sink in `vector/vector.toml`). This provides better performance than Filebeat for high event volumes.

### Option 4: Splunk

Coming soon. See `splunk/` directory for configuration examples.

## Multi-Host Deployments

LinMon now includes a `hostname` field in all events for multi-host SIEM deployments. This allows you to:

1. **Aggregate logs from multiple hosts** in a single database
2. **Query across hosts**: `SELECT * FROM events WHERE hostname = 'webserver01'`
3. **Alert on host-specific patterns**: Detect lateral movement, anomalous behavior per host
4. **Correlate events**: Track attacks that span multiple systems

Example ClickHouse query for multi-host correlation:
```sql
-- Find processes spawned by the same parent across different hosts
SELECT
    hostname,
    ppid,
    comm,
    count() as spawn_count
FROM linmon.events
WHERE type = 'process_exec'
  AND timestamp > now() - INTERVAL 1 HOUR
GROUP BY hostname, ppid, comm
HAVING spawn_count > 10
ORDER BY spawn_count DESC;
```

## Performance Comparison

| Solution | Ingestion Rate | Query Performance | Storage Efficiency | Complexity |
|----------|---------------|-------------------|-------------------|-----------|
| Vector + ClickHouse | 100k-1M events/sec | Excellent (columnar) | Excellent (10-40x compression) | Low |
| Vector + Elasticsearch | 50k-500k events/sec | Good (full-text search) | Good | Medium |
| Filebeat + Elasticsearch | 10k-100k events/sec | Good | Good | Medium |
| Filebeat + Logstash + ES | 5k-50k events/sec | Good | Good | High |

## Example Use Cases

### Security Operations Center (SOC)

**Stack**: Vector.dev → ClickHouse + Grafana

- Real-time dashboards showing security events across all hosts
- Materialized views for fast MITRE ATT&CK technique detection
- 90-day retention with automatic TTL cleanup
- Sub-second queries on billions of events

### Compliance and Forensics

**Stack**: Vector.dev → S3 (long-term) + ClickHouse (hot data)

- Archive all events to S3 for 7-year retention (compliance)
- Keep last 90 days in ClickHouse for fast queries
- Replay historical data from S3 when needed

### Development and Testing

**Stack**: Filebeat → Elasticsearch → Kibana

- Full-text search for debugging
- Pre-built Kibana dashboards
- Easy integration with existing ELK stack

## Next Steps

1. Choose your integration stack
2. Follow the Quick Start guide above
3. Explore the example queries in `clickhouse/schema.sql`
4. Customize dashboards and alerts for your environment
5. See [MONITORING.md](../MONITORING.md) for query examples and alerting patterns

## Contributing

Have a working integration with another platform? Please submit a pull request with:
- Configuration files
- README with setup instructions
- Example queries or dashboards
