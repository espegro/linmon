// SPDX-License-Identifier: GPL-2.0-or-later
// Unit tests for config.c - Configuration parsing and validation

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include "test_framework.h"
#include "../src/config.h"

// Helper to create temporary config file
static int create_temp_config(const char *content, char *path_out, size_t path_size)
{
    snprintf(path_out, path_size, "/tmp/linmon_test_config_XXXXXX");
    int fd = mkstemp(path_out);
    if (fd < 0)
        return -1;

    ssize_t written = write(fd, content, strlen(content));
    close(fd);

    if (written != (ssize_t)strlen(content)) {
        unlink(path_out);
        return -1;
    }

    return 0;
}

// Test default configuration values
static void test_config_defaults(void)
{
    TEST_CASE("Config: default values");

    struct linmon_config config;
    char path[256];

    // Create empty config file
    create_temp_config("# Empty config\n", path, sizeof(path));
    int ret = load_config(&config, path);
    unlink(path);

    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(config.monitor_processes);
    ASSERT_TRUE(config.monitor_process_exit);
    ASSERT_TRUE(config.monitor_tcp);
    ASSERT_FALSE(config.monitor_files);
    ASSERT_FALSE(config.monitor_udp);
    ASSERT_TRUE(config.capture_cmdline);
    ASSERT_TRUE(config.redact_sensitive);
    ASSERT_TRUE(config.resolve_usernames);
    ASSERT_TRUE(config.hash_binaries);
    ASSERT_EQ(config.min_uid, 0);
    ASSERT_EQ(config.max_uid, 0);
    ASSERT_EQ(config.verbosity, 1);
    ASSERT_EQ(config.log_rotate_count, 10);
    ASSERT_EQ(config.log_rotate_size, 100 * 1024 * 1024);

    free_config(&config);
}

// Test boolean parsing
static void test_config_boolean_parsing(void)
{
    TEST_CASE("Config: boolean parsing");

    struct linmon_config config;
    char path[256];
    const char *content =
        "monitor_processes = true\n"
        "monitor_files = false\n"
        "monitor_tcp = true\n"
        "capture_cmdline = false\n";

    create_temp_config(content, path, sizeof(path));
    int ret = load_config(&config, path);
    unlink(path);

    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(config.monitor_processes);
    ASSERT_FALSE(config.monitor_files);
    ASSERT_TRUE(config.monitor_tcp);
    ASSERT_FALSE(config.capture_cmdline);

    free_config(&config);
}

// Test integer parsing with validation
static void test_config_integer_parsing(void)
{
    TEST_CASE("Config: integer parsing and validation");

    struct linmon_config config;
    char path[256];
    const char *content =
        "min_uid = 1000\n"
        "max_uid = 60000\n"
        "verbosity = 2\n"
        "log_rotate_count = 5\n";

    create_temp_config(content, path, sizeof(path));
    int ret = load_config(&config, path);
    unlink(path);

    ASSERT_EQ(ret, 0);
    ASSERT_EQ(config.min_uid, 1000);
    ASSERT_EQ(config.max_uid, 60000);
    ASSERT_EQ(config.verbosity, 2);
    ASSERT_EQ(config.log_rotate_count, 5);

    free_config(&config);
}

// Test size parsing with K/M/G suffixes
static void test_config_size_parsing(void)
{
    TEST_CASE("Config: size parsing with K/M/G suffixes");

    struct linmon_config config;
    char path[256];

    // Test with M suffix
    const char *content_m = "log_rotate_size = 50M\n";
    create_temp_config(content_m, path, sizeof(path));
    int ret = load_config(&config, path);
    unlink(path);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(config.log_rotate_size, 50 * 1024 * 1024);
    free_config(&config);

    // Test with K suffix
    const char *content_k = "log_rotate_size = 2048K\n";
    create_temp_config(content_k, path, sizeof(path));
    ret = load_config(&config, path);
    unlink(path);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(config.log_rotate_size, 2048 * 1024);
    free_config(&config);

    // Test with G suffix
    const char *content_g = "log_rotate_size = 1G\n";
    create_temp_config(content_g, path, sizeof(path));
    ret = load_config(&config, path);
    unlink(path);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(config.log_rotate_size, 1024UL * 1024 * 1024);
    free_config(&config);

    // Test without suffix (bytes)
    const char *content_bytes = "log_rotate_size = 10485760\n";  // 10MB in bytes
    create_temp_config(content_bytes, path, sizeof(path));
    ret = load_config(&config, path);
    unlink(path);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(config.log_rotate_size, 10485760);
    free_config(&config);
}

// Test path validation (must be absolute)
static void test_config_path_validation(void)
{
    TEST_CASE("Config: path validation (absolute paths only)");

    struct linmon_config config;
    char path[256];

    // Valid absolute path
    const char *content_valid = "log_file = /var/log/linmon/events.json\n";
    create_temp_config(content_valid, path, sizeof(path));
    int ret = load_config(&config, path);
    unlink(path);
    ASSERT_EQ(ret, 0);
    ASSERT_STREQ(config.log_file, "/var/log/linmon/events.json");
    free_config(&config);

    // Invalid relative path (should be rejected)
    const char *content_relative = "log_file = var/log/linmon.json\n";
    create_temp_config(content_relative, path, sizeof(path));
    ret = load_config(&config, path);
    unlink(path);
    ASSERT_EQ(ret, 0);
    ASSERT_NULL(config.log_file);  // Should not be set
    free_config(&config);

    // Path with ".." (should be rejected for security)
    const char *content_dotdot = "log_file = /var/log/../tmp/linmon.json\n";
    create_temp_config(content_dotdot, path, sizeof(path));
    ret = load_config(&config, path);
    unlink(path);
    ASSERT_EQ(ret, 0);
    ASSERT_NULL(config.log_file);  // Should not be set
    free_config(&config);
}

// Test comment and empty line handling
static void test_config_comments_and_empty_lines(void)
{
    TEST_CASE("Config: comments and empty lines");

    struct linmon_config config;
    char path[256];
    const char *content =
        "# This is a comment\n"
        "\n"
        "monitor_processes = true\n"
        "# Another comment\n"
        "monitor_files = false\n"
        "\n"
        "# Final comment\n";

    create_temp_config(content, path, sizeof(path));
    int ret = load_config(&config, path);
    unlink(path);

    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(config.monitor_processes);
    ASSERT_FALSE(config.monitor_files);

    free_config(&config);
}

// Test invalid values are rejected
static void test_config_invalid_values(void)
{
    TEST_CASE("Config: invalid values are rejected");

    struct linmon_config config;
    char path[256];

    // Invalid verbosity (out of range 0-2)
    const char *content_verbosity = "verbosity = 5\n";
    create_temp_config(content_verbosity, path, sizeof(path));
    int ret = load_config(&config, path);
    unlink(path);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(config.verbosity, 1);  // Should use default
    free_config(&config);

    // Invalid log_rotate_count (out of range 1-100)
    const char *content_count = "log_rotate_count = 150\n";
    create_temp_config(content_count, path, sizeof(path));
    ret = load_config(&config, path);
    unlink(path);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(config.log_rotate_count, 10);  // Should use default
    free_config(&config);

    // Invalid size (too small, min 1M)
    const char *content_size = "log_rotate_size = 512K\n";
    create_temp_config(content_size, path, sizeof(path));
    ret = load_config(&config, path);
    unlink(path);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(config.log_rotate_size, 100 * 1024 * 1024);  // Should use default
    free_config(&config);
}

// Test string list parsing
static void test_config_string_lists(void)
{
    TEST_CASE("Config: string list parsing");

    struct linmon_config config;
    char path[256];
    const char *content =
        "ignore_processes = systemd,dbus-daemon,kworker\n"
        "ignore_networks = 127.0.0.0/8,10.0.0.0/8\n"
        "ignore_file_paths = /proc,/sys,/dev\n";

    create_temp_config(content, path, sizeof(path));
    int ret = load_config(&config, path);
    unlink(path);

    ASSERT_EQ(ret, 0);
    ASSERT_STREQ(config.ignore_processes, "systemd,dbus-daemon,kworker");
    ASSERT_STREQ(config.ignore_networks, "127.0.0.0/8,10.0.0.0/8");
    ASSERT_STREQ(config.ignore_file_paths, "/proc,/sys,/dev");

    free_config(&config);
}

// Test malformed lines are skipped
static void test_config_malformed_lines(void)
{
    TEST_CASE("Config: malformed lines are skipped");

    struct linmon_config config;
    char path[256];
    const char *content =
        "monitor_processes = true\n"
        "this is not a valid line\n"
        "key_without_value\n"
        "= value_without_key\n"
        "monitor_files = false\n";

    create_temp_config(content, path, sizeof(path));
    int ret = load_config(&config, path);
    unlink(path);

    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(config.monitor_processes);
    ASSERT_FALSE(config.monitor_files);

    free_config(&config);
}

// Test missing config file
static void test_config_missing_file(void)
{
    TEST_CASE("Config: missing file uses defaults");

    struct linmon_config config;
    int ret = load_config(&config, "/tmp/nonexistent_config_file_12345.conf");

    ASSERT_EQ(ret, -ENOENT);
    // Defaults should still be set
    ASSERT_TRUE(config.monitor_processes);
    ASSERT_TRUE(config.capture_cmdline);

    free_config(&config);
}

// Test security monitoring options
static void test_config_security_monitoring(void)
{
    TEST_CASE("Config: security monitoring options");

    struct linmon_config config;
    char path[256];
    const char *content =
        "monitor_ptrace = true\n"
        "monitor_modules = true\n"
        "monitor_memfd = true\n"
        "monitor_bind = true\n"
        "monitor_unshare = true\n"
        "monitor_execveat = true\n"
        "monitor_bpf = true\n"
        "monitor_cred_read = true\n"
        "monitor_ldpreload = true\n"
        "monitor_persistence = true\n"
        "monitor_suid = true\n"
        "monitor_cred_write = true\n"
        "monitor_log_tamper = true\n"
        "monitor_raw_disk_access = true\n";

    create_temp_config(content, path, sizeof(path));
    int ret = load_config(&config, path);
    unlink(path);

    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(config.monitor_ptrace);
    ASSERT_TRUE(config.monitor_modules);
    ASSERT_TRUE(config.monitor_memfd);
    ASSERT_TRUE(config.monitor_bind);
    ASSERT_TRUE(config.monitor_unshare);
    ASSERT_TRUE(config.monitor_execveat);
    ASSERT_TRUE(config.monitor_bpf);
    ASSERT_TRUE(config.monitor_cred_read);
    ASSERT_TRUE(config.monitor_ldpreload);
    ASSERT_TRUE(config.monitor_persistence);
    ASSERT_TRUE(config.monitor_suid);
    ASSERT_TRUE(config.monitor_cred_write);
    ASSERT_TRUE(config.monitor_log_tamper);
    ASSERT_TRUE(config.monitor_raw_disk_access);

    free_config(&config);
}

// Test cache configuration options
static void test_config_cache_options(void)
{
    TEST_CASE("Config: cache configuration options");

    struct linmon_config config;
    char path[256];
    const char *content =
        "hash_cache_size = 5000\n"
        "pkg_cache_size = 8000\n"
        "cache_save_interval = 10\n"
        "checkpoint_interval = 60\n";

    create_temp_config(content, path, sizeof(path));
    int ret = load_config(&config, path);
    unlink(path);

    ASSERT_EQ(ret, 0);
    ASSERT_EQ(config.hash_cache_size, 5000);
    ASSERT_EQ(config.pkg_cache_size, 8000);
    ASSERT_EQ(config.cache_save_interval, 10);
    ASSERT_EQ(config.checkpoint_interval, 60);

    free_config(&config);
}

// Test UID range configuration
static void test_config_uid_range(void)
{
    TEST_CASE("Config: UID range configuration");

    struct linmon_config config;
    char path[256];
    const char *content =
        "min_uid = 1000\n"
        "max_uid = 65534\n";

    create_temp_config(content, path, sizeof(path));
    int ret = load_config(&config, path);
    unlink(path);

    ASSERT_EQ(ret, 0);
    ASSERT_EQ(config.min_uid, 1000);
    ASSERT_EQ(config.max_uid, 65534);

    free_config(&config);
}

// Test network monitoring options
static void test_config_network_monitoring(void)
{
    TEST_CASE("Config: network monitoring options");

    struct linmon_config config;
    char path[256];
    const char *content =
        "monitor_tcp = true\n"
        "monitor_udp = true\n"
        "monitor_vsock = true\n";

    create_temp_config(content, path, sizeof(path));
    int ret = load_config(&config, path);
    unlink(path);

    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(config.monitor_tcp);
    ASSERT_TRUE(config.monitor_udp);
    ASSERT_TRUE(config.monitor_vsock);

    free_config(&config);
}

// Test world-writable config file is rejected
static void test_config_world_writable_rejected(void)
{
    TEST_CASE("Config: world-writable file is rejected");

    struct linmon_config config;
    char path[256];
    const char *content = "monitor_processes = true\n";

    create_temp_config(content, path, sizeof(path));

    // Make file world-writable
    chmod(path, 0666);

    int ret = load_config(&config, path);
    unlink(path);

    ASSERT_EQ(ret, -EPERM);  // Should reject world-writable config

    free_config(&config);
}

int main(void)
{
    TEST_SUITE("LinMon Config Tests - Parsing and Validation");

    test_config_defaults();
    test_config_boolean_parsing();
    test_config_integer_parsing();
    test_config_size_parsing();
    test_config_path_validation();
    test_config_comments_and_empty_lines();
    test_config_invalid_values();
    test_config_string_lists();
    test_config_malformed_lines();
    test_config_missing_file();
    test_config_security_monitoring();
    test_config_cache_options();
    test_config_uid_range();
    test_config_network_monitoring();
    test_config_world_writable_rejected();

    print_test_summary();

    return (tests_failed > 0) ? 1 : 0;
}
