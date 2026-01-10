PROJECT := linmon
DAEMON := linmond
VERSION := $(shell cat VERSION 2>/dev/null || echo "0.0.0")

# Directories
BUILD_DIR := build
SRC_DIR := src
BPF_DIR := bpf
OBJ_DIR := $(BUILD_DIR)/obj
BPF_OBJ_DIR := $(BUILD_DIR)/bpf

# Tools
CLANG := clang
LLC := llc
CC := gcc

# Auto-detect bpftool location (different on Ubuntu vs RHEL vs Debian)
# Try multiple locations in order:
# 1. System-wide bpftool (RHEL/Fedora style)
# 2. Debian /usr/sbin/bpftool (Raspberry Pi OS)
# 3. Ubuntu kernel-specific tools directories
# 4. Generic /usr/lib search
BPFTOOL := $(shell \
    if command -v bpftool >/dev/null 2>&1 && bpftool version >/dev/null 2>&1; then \
        command -v bpftool; \
    elif [ -x /usr/sbin/bpftool ] && /usr/sbin/bpftool version >/dev/null 2>&1; then \
        echo /usr/sbin/bpftool; \
    elif [ -n "$$(find /usr/lib/linux-tools -name bpftool -type f 2>/dev/null | head -n1)" ]; then \
        find /usr/lib/linux-tools -name bpftool -type f 2>/dev/null | head -n1; \
    elif [ -n "$$(find /usr/lib -name bpftool -type f 2>/dev/null | head -n1)" ]; then \
        find /usr/lib -name bpftool -type f 2>/dev/null | head -n1; \
    else \
        echo ""; \
    fi)

ifeq ($(BPFTOOL),)
    $(error bpftool not found. Install: Ubuntu: apt install linux-tools-generic | RHEL: dnf install bpftool)
endif

# Verify bpftool works
BPFTOOL_TEST := $(shell $(BPFTOOL) version >/dev/null 2>&1 && echo OK)
ifneq ($(BPFTOOL_TEST),OK)
    $(error bpftool found at $(BPFTOOL) but doesn't work. Check installation.)
endif

# Auto-detect architecture
ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
    ARCH_DEFINE := -D__TARGET_ARCH_arm64
else ifeq ($(ARCH),x86_64)
    ARCH_DEFINE := -D__TARGET_ARCH_x86
else
    $(error Unsupported architecture: $(ARCH). Supported: x86_64, aarch64)
endif

# Flags
INCLUDES := -I/usr/include -I$(BPF_DIR) -I$(SRC_DIR)
CFLAGS := -Wall -Wextra -O2 -g $(INCLUDES) -DLINMON_VERSION=\"$(VERSION)\"
BPF_CFLAGS := -target bpf $(ARCH_DEFINE) -Wall -O2 -g $(INCLUDES)
LDFLAGS := -lbpf -lelf -lz -lpthread -lcrypto -lcap

# Source files
BPF_SOURCES := $(wildcard $(BPF_DIR)/*.bpf.c)
BPF_OBJECTS := $(patsubst $(BPF_DIR)/%.bpf.c,$(BPF_OBJ_DIR)/%.bpf.o,$(BPF_SOURCES))
BPF_SKELS := $(patsubst $(BPF_DIR)/%.bpf.c,$(SRC_DIR)/%.skel.h,$(BPF_SOURCES))

DAEMON_SOURCES := $(wildcard $(SRC_DIR)/*.c)
DAEMON_OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(DAEMON_SOURCES))

# Targets
.PHONY: all clean install uninstall

all: $(BUILD_DIR)/$(DAEMON)

# Create directories
$(BUILD_DIR) $(OBJ_DIR) $(BPF_OBJ_DIR):
	mkdir -p $@

# Compile BPF programs
$(BPF_OBJ_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c | $(BPF_OBJ_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	llvm-strip -g $@

# Generate BPF skeletons
$(SRC_DIR)/%.skel.h: $(BPF_OBJ_DIR)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Compile daemon source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(BPF_SKELS) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link daemon
$(BUILD_DIR)/$(DAEMON): $(DAEMON_OBJECTS) | $(BUILD_DIR)
	$(CC) $(DAEMON_OBJECTS) $(LDFLAGS) -o $@

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(SRC_DIR)/*.skel.h

install: $(BUILD_DIR)/$(DAEMON)
	install -D -m 755 $(BUILD_DIR)/$(DAEMON) /usr/local/sbin/$(DAEMON)
	install -D -m 644 $(DAEMON).service /etc/systemd/system/$(DAEMON).service
	mkdir -p /etc/linmon
	# Always install .example as reference (for comparing new options)
	install -D -m 644 linmon.conf.example /etc/linmon/linmon.conf.example
	# Only install actual config on first install (never overwrite user config)
	@if [ ! -f /etc/linmon/linmon.conf ]; then \
		echo "Installing default configuration to /etc/linmon/linmon.conf"; \
		install -D -m 600 linmon.conf /etc/linmon/linmon.conf; \
	else \
		echo "Existing configuration found at /etc/linmon/linmon.conf (preserving)"; \
		echo ""; \
		echo "Checking for new configuration options in v$(VERSION)..."; \
		MISSING_CRED_WRITE=$$(grep -q "^monitor_cred_write =" /etc/linmon/linmon.conf 2>/dev/null && echo "no" || echo "yes"); \
		MISSING_LOG_TAMPER=$$(grep -q "^monitor_log_tamper =" /etc/linmon/linmon.conf 2>/dev/null && echo "no" || echo "yes"); \
		if [ "$$MISSING_CRED_WRITE" = "yes" ] || [ "$$MISSING_LOG_TAMPER" = "yes" ]; then \
			echo ""; \
			echo "⚠️  NEW in v1.4.1 - Critical security options missing from your config:"; \
			if [ "$$MISSING_CRED_WRITE" = "yes" ]; then \
				echo "  ✗ monitor_cred_write  (T1098.001 - Account manipulation detection)"; \
			fi; \
			if [ "$$MISSING_LOG_TAMPER" = "yes" ]; then \
				echo "  ✗ monitor_log_tamper  (T1070.001 - Log tampering detection)"; \
			fi; \
			echo ""; \
			echo "These features are ENABLED BY DEFAULT but not in your config."; \
			echo "Add to /etc/linmon/linmon.conf:"; \
			echo ""; \
			grep -E '^(monitor_cred_write|monitor_log_tamper) ' /etc/linmon/linmon.conf.example; \
			echo ""; \
			echo "Then reload: systemctl reload linmond"; \
		else \
			echo "✓ Configuration includes all v$(VERSION) options"; \
		fi; \
		echo ""; \
		echo "Full reference config: /etc/linmon/linmon.conf.example"; \
		TOTAL_MISSING=$$(grep -E '^[a-z_]+ =' /etc/linmon/linmon.conf.example | cut -d= -f1 | while read opt; do \
			if ! grep -q "^$$opt =" /etc/linmon/linmon.conf 2>/dev/null; then \
				echo "$$opt"; \
			fi; \
		done | wc -l); \
		if [ $$TOTAL_MISSING -gt 2 ]; then \
			echo "Note: $$TOTAL_MISSING total options missing (not all are new)"; \
			echo "      Compare: diff /etc/linmon/linmon.conf /etc/linmon/linmon.conf.example"; \
		fi; \
		echo ""; \
	fi
	mkdir -p /var/log/linmon
	mkdir -p /var/cache/linmon
	@if getent group nogroup >/dev/null 2>&1; then \
		chown nobody:nogroup /var/log/linmon /var/cache/linmon; \
		sed 's/nobody nogroup/nobody nogroup/' $(DAEMON).logrotate > /etc/logrotate.d/$(DAEMON); \
	else \
		chown nobody:nobody /var/log/linmon /var/cache/linmon; \
		sed 's/nobody nogroup/nobody nobody/' $(DAEMON).logrotate > /etc/logrotate.d/$(DAEMON); \
	fi
	chmod 0644 /etc/logrotate.d/$(DAEMON)
	chmod 0750 /var/log/linmon /var/cache/linmon
	# Fix permissions on existing log files (defense in depth)
	@if [ -f /var/log/linmon/events.json ]; then \
		echo "Fixing permissions on existing log file..."; \
		chmod 0640 /var/log/linmon/events.json; \
	fi
	# Fix permissions on rotated log files
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		if [ -f /var/log/linmon/events.json.$$i ]; then \
			chmod 0640 /var/log/linmon/events.json.$$i; \
		fi; \
	done
	systemctl daemon-reload
	@echo ""
	@echo "Installation complete. Use 'systemctl start linmond' to start the service."

uninstall:
	systemctl stop $(DAEMON) || true
	systemctl disable $(DAEMON) || true
	rm -f /usr/local/sbin/$(DAEMON)
	rm -f /etc/systemd/system/$(DAEMON).service
	rm -f /etc/logrotate.d/$(DAEMON)
	systemctl daemon-reload
