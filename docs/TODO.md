# LinMon TODO - BPF Load Hardening & Architecture Cleanup

## Overview

Etter analyse av Singularity rootkit og diskusjon om LKRG-dependencies, følgende må implementeres:

---

## ✅ CORE Functionality (No External Dependencies)

### 1. Enhanced BPF Load Failure Logging

**Mål**: Persistent logging når BPF programs ikke kan lastes (f.eks. blokkert av Singularity).

**Filer som må endres**:
- `src/main.c` (rundt linje 934-939)

**Hva skal implementeres**:

```c
// Around line 934 in src/main.c
skel = linmon_bpf__open_and_load();
if (!skel) {
    int bpf_errno = errno;
    const char *error_msg = strerror(bpf_errno);

    // 1. Log to syslog (persistent, survives daemon exit)
    syslog(LOG_CRIT,
           "CRITICAL: Failed to load BPF programs: %s (errno=%d). "
           "Possible rootkit interference. "
           "Verify: 1) Kernel >= 5.8, 2) BTF support, 3) No bpf() blocking",
           error_msg, bpf_errno);

    // 2. Create alert file (forensic evidence)
    FILE *alert_fp = fopen("/var/log/linmon/CRITICAL_BPF_LOAD_FAILED", "w");
    if (alert_fp) {
        fprintf(alert_fp, "Time: %s\n", ctime(&daemon_start_time));
        fprintf(alert_fp, "Error: %s (errno=%d)\n", error_msg, bpf_errno);
        fprintf(alert_fp, "Investigate: dmesg | grep -E '(bpf|module|LKRG)'\n");
        fclose(alert_fp);
    }

    // 3. Detailed stderr for systemd journal
    fprintf(stderr, "CRITICAL: BPF loading failed - %s\n", error_msg);
    fprintf(stderr, "Possible causes:\n");
    fprintf(stderr, "  1. Kernel rootkit blocking bpf() syscall\n");
    fprintf(stderr, "  2. Missing BTF support (/sys/kernel/btf/vmlinux)\n");
    fprintf(stderr, "  3. Insufficient privileges (need CAP_BPF)\n");

    err = -1;
    goto cleanup;
}

// Success path - log that BPF loaded OK (tamper detection)
syslog(LOG_INFO, "BPF programs loaded successfully");
```

**Testing**:
```bash
# Simulate BPF load failure (requires LKRG or similar)
# Expected: Alert file created, syslog entry, stderr message

# Check logs
sudo journalctl -u linmond --since "1 minute ago"
cat /var/log/linmon/CRITICAL_BPF_LOAD_FAILED
```

**Status**: ⏳ Pending
**Priority**: **HIGH** (critical for rootkit detection)
**Dependencies**: None (only stdlib, syslog)

---

## 📦 EXTRAS Functionality (Optional, External Dependencies)

### 2. Move LKRG-Dependent Scripts to extras/

**Mål**: Separere core LinMon fra optional LKRG integration.

**Struktur**:
```
linmon/
├── scripts/             # Core scripts (no dependencies)
│   ├── harden-system.sh
│   ├── test-rootkit-defenses.sh
│   └── README.md
│
└── extras/              # Optional features (external dependencies)
    ├── lkrg/
    │   ├── linmon-enable-lockdown.sh       # LKRG integration
    │   ├── linmon-check-lockdown.sh        # Status checker
    │   ├── setup-failure-alerting.sh       # Systemd alerts
    │   ├── linmon-failure-alert.sh         # Alert handler
    │   └── README.md                       # LKRG requirements
    │
    └── README.md        # Extras overview
```

**Flytt disse filene**:
- `scripts/linmon-enable-lockdown.sh` → `extras/lkrg/`
- `scripts/linmon-check-lockdown.sh` → `extras/lkrg/`
- `scripts/setup-failure-alerting.sh` → `extras/lkrg/`
- `scripts/linmon-failure-alert.sh` → `extras/lkrg/`

**Oppdater disse filene**:
- `scripts/README.md` - fjern LKRG-scripts, legg til link til extras/
- Lag `extras/README.md` - forklar optional features
- Lag `extras/lkrg/README.md` - LKRG installation guide

**Status**: ⏳ Pending
**Priority**: MEDIUM (cleanup, not critical functionality)

---

## 🔑 Module Signing Configuration

### 3. Non-Hardcoded Signing Key Path

**Problem**: Signing keys skal IKKE hardkodes i scripts.

**Current situation**:
- Module signing ville typisk bruke hardcoded paths i build scripts
- Ikke fleksibelt, ikke secure

**Løsning**: Configuration-based signing

**Implementering**:

#### Option A: Environment Variable (Recommended)

```bash
# /etc/linmon/signing.conf (optional file)
# If this file exists, LinMon build will sign BPF programs
LINMON_SIGNING_KEY=/etc/linmon/keys/linmon-bpf-signing.key
LINMON_SIGNING_CERT=/etc/linmon/keys/linmon-bpf-signing.crt
```

**Makefile changes**:
```make
# Check if signing config exists
-include /etc/linmon/signing.conf

ifdef LINMON_SIGNING_KEY
    # Sign BPF objects after compilation
    $(BPF_OBJ_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c | $(BPF_OBJ_DIR)
        $(CLANG) $(BPF_CFLAGS) -c $< -o $@
        llvm-strip -g $@
        # Sign if key configured
        @if [ -f "$(LINMON_SIGNING_KEY)" ]; then \
            echo "Signing BPF object: $@"; \
            /lib/modules/$$(uname -r)/build/scripts/sign-file \
                sha256 $(LINMON_SIGNING_KEY) $(LINMON_SIGNING_CERT) $@; \
        fi
else
    # No signing - regular build
    $(BPF_OBJ_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c | $(BPF_OBJ_DIR)
        $(CLANG) $(BPF_CFLAGS) -c $< -o $@
        llvm-strip -g $@
endif
```

**Key generation script** (`extras/signing/generate-signing-keys.sh`):
```bash
#!/bin/bash
# Generate BPF signing keys for LinMon

KEY_DIR=/etc/linmon/keys
mkdir -p "$KEY_DIR"

# Generate key pair
openssl req -new -x509 -newkey rsa:2048 \
    -keyout "$KEY_DIR/linmon-bpf-signing.key" \
    -outform DER \
    -out "$KEY_DIR/linmon-bpf-signing.crt" \
    -nodes \
    -days 36500 \
    -subj "/CN=LinMon BPF Signing Key/"

chmod 600 "$KEY_DIR/linmon-bpf-signing.key"
chmod 644 "$KEY_DIR/linmon-bpf-signing.crt"

# Create signing config
cat > /etc/linmon/signing.conf <<EOF
# LinMon BPF Signing Configuration
LINMON_SIGNING_KEY=$KEY_DIR/linmon-bpf-signing.key
LINMON_SIGNING_CERT=$KEY_DIR/linmon-bpf-signing.crt
EOF

echo "✓ Signing keys generated in $KEY_DIR"
echo "✓ Config written to /etc/linmon/signing.conf"
echo ""
echo "Next steps:"
echo "  1. Rebuild LinMon: make clean && make"
echo "  2. BPF objects will be automatically signed"
echo ""
echo "For Secure Boot integration:"
echo "  sudo mokutil --import $KEY_DIR/linmon-bpf-signing.crt"
```

#### Option B: Build-time Parameter

```bash
# Pass signing key at build time
make SIGN_KEY=/path/to/key.pem SIGN_CERT=/path/to/cert.pem
```

**Recommendation**: Option A (config file) er mer flexibel for production.

**Status**: ⏳ Pending
**Priority**: LOW (BPF signing is not strictly required, only for paranoid environments)

**Note**:
- eBPF programs loaded via libbpf (userspace) **do not need signing** like LKMs do
- Signing eBPF is only needed for BPF LSM hooks (not used by LinMon)
- This task kan droppes hvis ikke relevant for LinMon's threat model

---

## 📚 Documentation Updates

### 4. Separate Core vs Extras Documentation

**Oppdater**:

#### `README.md` (main)
- Clearly state "No external dependencies for core functionality"
- Mention extras/ for optional LKRG integration

#### `docs/ROOTKIT_PREVENTION.md`
- Section 1: Core protections (Secure Boot, Lockdown, AppArmor)
- Section 2: Optional LKRG integration (link to extras/)

#### `scripts/README.md`
- Remove all LKRG-specific scripts
- Add note: "For LKRG integration, see extras/lkrg/"

#### `extras/README.md` (NEW)
```markdown
# LinMon Extras

Optional features with external dependencies.

## LKRG Integration (extras/lkrg/)

**Dependency**: Linux Kernel Runtime Guard (lkrg-dkms)

Provides runtime module blocking after LinMon loads.
See: extras/lkrg/README.md

## BPF Signing (extras/signing/)

**Dependency**: OpenSSL, kernel signing tools

For paranoid environments requiring signed eBPF programs.
See: extras/signing/README.md
```

**Status**: ⏳ Pending
**Priority**: MEDIUM (important for clarity)

---

## 🎯 Implementation Priority

| Priority | Task | Reason | Dependencies |
|----------|------|--------|--------------|
| **HIGH** | BPF load failure logging | Critical for rootkit detection | None |
| MEDIUM | Move LKRG to extras/ | Cleanup, not critical | None |
| MEDIUM | Documentation updates | Important for users | None |
| LOW | Signing key config | Optional feature | OpenSSL (if used) |

---

## ✅ Summary of Changes

### What LinMon REQUIRES (core):
- ✅ Kernel >= 5.8 with BTF support
- ✅ libbpf, libelf, zlib
- ✅ Standard C libraries
- **❌ NO LKRG dependency**
- **❌ NO signing required**

### What LinMon OPTIONALLY supports (extras/):
- ⚠️ LKRG integration (runtime module blocking)
- ⚠️ BPF signing (for paranoid environments)
- ⚠️ Email alerting (via mail command)

### Architecture:
```
Core LinMon:
  - eBPF monitoring (always works)
  - BPF load failure detection (always works)
  - Logging to JSON + syslog (always works)

Extras (opt-in):
  - LKRG lockdown-after-load (requires lkrg-dkms)
  - Systemd failure alerts (requires systemd)
  - Email alerts (requires mail command)
```

---

## Next Steps

1. **Implement BPF load failure logging** (HIGH priority)
   - Patch `src/main.c`
   - Test with simulated failure
   - Verify syslog entries persist

2. **Restructure repository** (MEDIUM priority)
   - Create `extras/` directory
   - Move LKRG scripts
   - Update READMEs

3. **Update documentation** (MEDIUM priority)
   - Clear separation between core and extras
   - Installation guide without LKRG
   - Optional LKRG integration guide

4. **Drop or defer BPF signing** (LOW priority)
   - Not strictly needed for LinMon's threat model
   - Can be added later if required

---

## Questions for Consideration

1. **BPF signing**: Er dette relevant for LinMon? eBPF programs loaded via libbpf (userspace) trenger ikke signering som LKMs gjør.

2. **LKRG fallback**: Når LKRG ikke er tilgjengelig, skal LinMon:
   - A) Bare logge en warning? (current behavior)
   - B) Foreslå native kernel lockdown boot parameter?
   - C) Exit med error hvis lockdown er påkrevd?

3. **Systemd dependency**: Er systemd OK som optional dependency for failure alerts? Eller skal det også flyttes til extras/?

---

## Implementation Checklist

- [ ] Patch `src/main.c` with enhanced BPF load failure logging
- [ ] Create `extras/` directory structure
- [ ] Move LKRG scripts to `extras/lkrg/`
- [ ] Create `extras/README.md`
- [ ] Create `extras/lkrg/README.md`
- [ ] Update main `README.md` (no external deps statement)
- [ ] Update `docs/ROOTKIT_PREVENTION.md` (core vs extras)
- [ ] Update `scripts/README.md` (remove LKRG references)
- [ ] Test BPF load failure logging
- [ ] Test LinMon works without LKRG installed
- [ ] Update `CLAUDE.md` with architecture decisions
