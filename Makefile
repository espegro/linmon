PROJECT := linmon
DAEMON := linmond

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

# Auto-detect bpftool location (different on Ubuntu vs RHEL)
# Try multiple locations in order:
# 1. System-wide bpftool (RHEL/Fedora style)
# 2. Ubuntu kernel-specific tools directories
# 3. Generic /usr/bin or /usr/sbin
BPFTOOL := $(shell \
    if command -v bpftool >/dev/null 2>&1 && bpftool version >/dev/null 2>&1; then \
        command -v bpftool; \
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

# Flags
INCLUDES := -I/usr/include -I$(BPF_DIR) -I$(SRC_DIR)
CFLAGS := -Wall -Wextra -O2 -g $(INCLUDES)
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_x86 -Wall -O2 -g $(INCLUDES)
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
	install -D -m 644 $(DAEMON).logrotate /etc/logrotate.d/$(DAEMON)
	mkdir -p /etc/linmon
	if [ ! -f /etc/linmon/linmon.conf ]; then \
		install -D -m 600 linmon.conf /etc/linmon/linmon.conf; \
	fi
	mkdir -p /var/log/linmon
	chown nobody:nogroup /var/log/linmon
	chmod 0750 /var/log/linmon
	systemctl daemon-reload

uninstall:
	systemctl stop $(DAEMON) || true
	systemctl disable $(DAEMON) || true
	rm -f /usr/local/sbin/$(DAEMON)
	rm -f /etc/systemd/system/$(DAEMON).service
	rm -f /etc/logrotate.d/$(DAEMON)
	systemctl daemon-reload
