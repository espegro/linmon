# LinMon Watchdog

A lightweight health monitoring system for LinMon that detects failures systemd restart alone cannot catch.

## What It Detects

| Issue | systemd restart | Watchdog |
|-------|----------------|----------|
| Process crashes | ✅ Restarts | ✅ Detects + alerts |
| Process killed by malware | ✅ Restarts | ✅ Detects tampering attempt |
| Process hangs (deadlock) | ❌ No restart | ✅ Detects no logging |
| eBPF programs unloaded | ❌ Process still runs | ✅ Detects no events |
| Log file issues | ❌ Process still runs | ✅ Detects corrupt logging |
| Unauthorized service stop | ❌ Expected stop | ✅ Alerts on manual stop |
| Immutable flags removed | ❌ No check | ✅ Detects tampering |
| Binary modified | ❌ No check | ✅ Checksum verification |

## Installation

```bash
# Copy watchdog script
sudo install -m 755 scripts/linmon-watchdog.sh /usr/local/bin/linmon-watchdog.sh

# Install systemd units
sudo install -m 644 linmon-watchdog.service /etc/systemd/system/
sudo install -m 644 linmon-watchdog.timer /etc/systemd/system/

# Enable and start timer
sudo systemctl daemon-reload
sudo systemctl enable linmon-watchdog.timer
sudo systemctl start linmon-watchdog.timer
```

## Configuration

Edit `/usr/local/bin/linmon-watchdog.sh` to configure:

```bash
MAX_AGE_SECONDS=300      # Alert if no events for 5 minutes
ALERT_EMAIL="admin@example.com"  # Optional email alerts
```

## Checks Performed

1. **Service Running** - Verifies systemd unit is active
2. **Process Alive** - Confirms linmond process exists
3. **Events Recent** - Checks log file was written to in last 5 minutes
4. **Immutable Flags** - Verifies binary and config are protected
5. **Binary Integrity** - Compares SHA256 checksum to baseline
6. **Memory Usage** - Alerts if memory usage exceeds limit

## Manual Check

```bash
sudo /usr/local/bin/linmon-watchdog.sh
```

## Monitoring

```bash
# View watchdog logs
journalctl -u linmon-watchdog -f

# Check timer status
systemctl status linmon-watchdog.timer

# Check last run results
systemctl status linmon-watchdog.service
```

## SIEM Integration

Watchdog alerts are logged to syslog with structured format:

```
linmon-watchdog: severity=CRITICAL message="linmond service is not running"
```

Configure your SIEM to alert on `linmon-watchdog` events with severity `CRITICAL` or `WARNING`.

## Disabling

```bash
sudo systemctl stop linmon-watchdog.timer
sudo systemctl disable linmon-watchdog.timer
```

## When to Use

**Recommended for:**
- Production servers
- Security-critical systems
- Systems where LinMon is primary security monitoring
- Air-gapped environments (can't rely on external monitoring)

**Optional for:**
- Development/test systems
- Systems with comprehensive external monitoring
- Low-risk workstations

## Performance Impact

- **CPU:** Negligible (~1-2ms every 5 minutes)
- **Memory:** None (one-shot service)
- **Disk I/O:** Minimal (reads log file metadata)
- **Network:** None (unless email alerts configured)

## Security Considerations

The watchdog itself runs with minimal privileges:
- `NoNewPrivileges=true` - Cannot escalate privileges
- `ProtectSystem=strict` - Read-only system access
- `ReadWritePaths=/var/log` - Only log directory writable

## Limitations

- **Cannot prevent tampering** - Only detects after the fact
- **5-minute detection window** - Sophisticated attackers may work within timer interval
- **Depends on systemd** - If systemd is compromised, watchdog may fail

For defense-in-depth, combine with:
- External monitoring (Nagios, Prometheus, etc.)
- File integrity monitoring (AIDE, Tripwire)
- SELinux/AppArmor policies
