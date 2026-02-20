PROJECT := linmon
DAEMON := linmond
VERSION := $(shell cat VERSION 2>/dev/null || echo "0.0.0")

# Directories
BUILD_DIR := build
SRC_DIR := src
BPF_DIR := bpf
TEST_DIR := tests
OBJ_DIR := $(BUILD_DIR)/obj
BPF_OBJ_DIR := $(BUILD_DIR)/bpf
TEST_BIN_DIR := $(BUILD_DIR)/tests

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

# Test configuration
TEST_SOURCES := $(wildcard $(TEST_DIR)/*.c)
TEST_BINS := $(patsubst $(TEST_DIR)/%.c,$(TEST_BIN_DIR)/%,$(TEST_SOURCES))
TEST_CFLAGS := -Wall -Wextra -O2 -g $(INCLUDES)

# Targets
.PHONY: all clean install uninstall test

all: $(BUILD_DIR)/$(DAEMON)

# Create directories
$(BUILD_DIR) $(OBJ_DIR) $(BPF_OBJ_DIR) $(TEST_BIN_DIR):
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

# Test targets

# Compile test for filter.c
$(TEST_BIN_DIR)/test_filter: $(TEST_DIR)/test_filter.c $(SRC_DIR)/filter.c $(SRC_DIR)/config.c | $(TEST_BIN_DIR)
	$(CC) $(TEST_CFLAGS) $^ -o $@

# Compile test for logger.c (only tests json_escape function, duplicated in test)
$(TEST_BIN_DIR)/test_logger: $(TEST_DIR)/test_logger.c | $(TEST_BIN_DIR)
	$(CC) $(TEST_CFLAGS) $< -o $@

# Compile test for config.c
$(TEST_BIN_DIR)/test_config: $(TEST_DIR)/test_config.c $(SRC_DIR)/config.c | $(TEST_BIN_DIR)
	$(CC) $(TEST_CFLAGS) $^ -o $@

# Compile test for procfs.c
$(TEST_BIN_DIR)/test_procfs: $(TEST_DIR)/test_procfs.c $(SRC_DIR)/procfs.c | $(TEST_BIN_DIR)
	$(CC) $(TEST_CFLAGS) $^ -o $@

# Compile test for utils.c
$(TEST_BIN_DIR)/test_utils: $(TEST_DIR)/test_utils.c $(SRC_DIR)/utils.c | $(TEST_BIN_DIR)
	$(CC) $(TEST_CFLAGS) $^ -o $@

# Run all tests
test: $(TEST_BINS)
	@echo ""
	@echo "Running LinMon Unit Tests..."
	@echo "=============================="
	@for test in $(TEST_BINS); do \
		echo ""; \
		LINMON_TEST_MODE=1 $$test || exit 1; \
	done
	@echo ""
	@echo "=============================="
	@echo "All tests passed!"
	@echo ""

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(SRC_DIR)/*.skel.h

install: $(BUILD_DIR)/$(DAEMON)
	@echo "Running installation script..."
	@chmod +x install.sh
	@./install.sh
	@echo "Note: Binary and config are protected with immutable flag."
	@echo "To modify config: chattr -i /etc/linmon/linmon.conf, edit, then chattr +i"
	@echo "To upgrade: run 'make install' (automatically handles immutable flags)"

uninstall:
	systemctl stop $(DAEMON) || true
	systemctl disable $(DAEMON) || true
	# Remove immutable flags before deletion
	@chattr -i /usr/local/sbin/$(DAEMON) 2>/dev/null || true
	@chattr -i /etc/linmon/linmon.conf 2>/dev/null || true
	rm -f /usr/local/sbin/$(DAEMON)
	rm -f /etc/systemd/system/$(DAEMON).service
	rm -f /etc/logrotate.d/$(DAEMON)
	systemctl daemon-reload
