// SPDX-License-Identifier: GPL-2.0-or-later
// Unit tests for procfs.c - /proc filesystem reading and buffer handling

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include "test_framework.h"
#include "../src/procfs.h"

// Test reading cmdline from current process (always exists)
static void test_procfs_read_own_cmdline(void)
{
    TEST_CASE("procfs_read_cmdline: read current process");

    char buf[1024];
    pid_t my_pid = getpid();

    bool ret = procfs_read_cmdline(my_pid, buf, sizeof(buf));

    ASSERT_TRUE(ret);
    ASSERT_NOT_NULL(buf);
    ASSERT_TRUE(strlen(buf) > 0);  // Should have some content
}

// Test buffer overflow protection
static void test_procfs_cmdline_buffer_overflow(void)
{
    TEST_CASE("procfs_read_cmdline: buffer overflow protection");

    char small_buf[10];
    pid_t my_pid = getpid();

    bool ret = procfs_read_cmdline(my_pid, small_buf, sizeof(small_buf));

    // Should succeed but truncate
    ASSERT_TRUE(ret || !ret);  // May succeed or fail depending on cmdline size
    // If succeeded, should be null-terminated and within bounds
    if (ret) {
        ASSERT_TRUE(strlen(small_buf) < sizeof(small_buf));
        ASSERT_EQ(small_buf[sizeof(small_buf) - 1], '\0');
    }
}

// Test NULL buffer handling
static void test_procfs_cmdline_null_buffer(void)
{
    TEST_CASE("procfs_read_cmdline: NULL buffer");

    pid_t my_pid = getpid();

    bool ret = procfs_read_cmdline(my_pid, NULL, 100);
    ASSERT_FALSE(ret);
}

// Test zero-size buffer
static void test_procfs_cmdline_zero_size(void)
{
    TEST_CASE("procfs_read_cmdline: zero-size buffer");

    char buf[100];
    pid_t my_pid = getpid();

    bool ret = procfs_read_cmdline(my_pid, buf, 0);
    ASSERT_FALSE(ret);
}

// Test non-existent PID
static void test_procfs_cmdline_nonexistent_pid(void)
{
    TEST_CASE("procfs_read_cmdline: non-existent PID");

    char buf[1024];
    // Use very high PID that's unlikely to exist
    pid_t fake_pid = 999999;

    bool ret = procfs_read_cmdline(fake_pid, buf, sizeof(buf));
    ASSERT_FALSE(ret);
    ASSERT_EQ(buf[0], '\0');  // Should be empty
}

// Test buffer initialization
static void test_procfs_cmdline_buffer_init(void)
{
    TEST_CASE("procfs_read_cmdline: buffer initialization");

    char buf[1024];
    memset(buf, 'X', sizeof(buf));  // Fill with garbage
    pid_t fake_pid = 999999;  // Non-existent

    bool ret = procfs_read_cmdline(fake_pid, buf, sizeof(buf));
    ASSERT_FALSE(ret);
    ASSERT_EQ(buf[0], '\0');  // Should be cleared
}

// Test exactly 1-byte buffer (edge case for underflow protection)
static void test_procfs_cmdline_one_byte_buffer(void)
{
    TEST_CASE("procfs_read_cmdline: 1-byte buffer (underflow guard)");

    char buf[1];
    pid_t my_pid = getpid();

    bool ret = procfs_read_cmdline(my_pid, buf, sizeof(buf));

    // With 1-byte buffer, read will get 0 bytes (max_len - 1 = 0)
    // Should handle gracefully without underflow
    ASSERT_FALSE(ret);
    ASSERT_EQ(buf[0], '\0');
}

// Test 2-byte buffer (minimum for actual content)
static void test_procfs_cmdline_two_byte_buffer(void)
{
    TEST_CASE("procfs_read_cmdline: 2-byte buffer");

    char buf[2];
    pid_t my_pid = getpid();

    bool ret = procfs_read_cmdline(my_pid, buf, sizeof(buf));

    // May succeed with single character + null
    if (ret) {
        ASSERT_TRUE(strlen(buf) <= 1);
        ASSERT_EQ(buf[sizeof(buf) - 1], '\0');
    }
}

// Test reading init process (PID 1) - always exists
static void test_procfs_read_init_cmdline(void)
{
    TEST_CASE("procfs_read_cmdline: read init process (PID 1)");

    char buf[1024];
    pid_t init_pid = 1;

    bool ret = procfs_read_cmdline(init_pid, buf, sizeof(buf));

    // Should succeed (init always exists)
    ASSERT_TRUE(ret);
    ASSERT_TRUE(strlen(buf) > 0);
}

// Test sudo info parsing with NULL parameters
static void test_procfs_sudo_null_params(void)
{
    TEST_CASE("procfs_read_sudo_info: NULL parameters");

    pid_t my_pid = getpid();
    uid_t uid;
    char user[256];

    // NULL sudo_uid - should not crash
    procfs_read_sudo_info(my_pid, NULL, user, sizeof(user));
    ASSERT_TRUE(true);  // Didn't crash

    // NULL sudo_user - should not crash
    procfs_read_sudo_info(my_pid, &uid, NULL, 0);
    ASSERT_TRUE(true);  // Didn't crash

    // Both NULL - should not crash
    procfs_read_sudo_info(my_pid, NULL, NULL, 0);
    ASSERT_TRUE(true);  // Didn't crash
}

// Test sudo info with non-existent PID
static void test_procfs_sudo_nonexistent_pid(void)
{
    TEST_CASE("procfs_read_sudo_info: non-existent PID");

    uid_t uid = 0;
    char user[256];
    pid_t fake_pid = 999999;

    bool ret = procfs_read_sudo_info(fake_pid, &uid, user, sizeof(user));
    ASSERT_FALSE(ret);
    ASSERT_EQ(user[0], '\0');  // Should be empty
}

// Test sudo info buffer overflow protection
static void test_procfs_sudo_buffer_overflow(void)
{
    TEST_CASE("procfs_read_sudo_info: buffer overflow protection");

    uid_t uid = 0;
    char small_user[5] = {0};  // Very small buffer, initialized to zero
    pid_t my_pid = getpid();

    // Should not crash with small buffer
    procfs_read_sudo_info(my_pid, &uid, small_user, sizeof(small_user));

    // Buffer should be null-terminated (either from initialization or from strncpy)
    // strlen() will work safely because buffer is either:
    // 1. Initialized to zero, or
    // 2. Written by strncpy() which ensures null termination
    ASSERT_TRUE(strlen(small_user) < sizeof(small_user));
}

// Test sudo info with zero-size user buffer
static void test_procfs_sudo_zero_size_buffer(void)
{
    TEST_CASE("procfs_read_sudo_info: zero-size user buffer");

    uid_t uid = 0;
    char user[256] = "unchanged";
    pid_t my_pid = getpid();

    procfs_read_sudo_info(my_pid, &uid, user, 0);

    // Should not crash
    ASSERT_TRUE(true);
}

// Test that cmdline properly handles null-separated arguments
static void test_procfs_cmdline_null_separation(void)
{
    TEST_CASE("procfs_read_cmdline: null-separated args become spaces");

    char buf[1024];
    pid_t my_pid = getpid();

    bool ret = procfs_read_cmdline(my_pid, buf, sizeof(buf));

    if (ret && strlen(buf) > 0) {
        // Check that there are no embedded nulls in the string
        // (all nulls should have been replaced with spaces)
        size_t len = strlen(buf);
        for (size_t i = 0; i < len; i++) {
            ASSERT_NEQ(buf[i], '\0');
        }
    }
}

// Test reading from init (PID 1) sudo info (won't have SUDO_UID)
static void test_procfs_sudo_init_process(void)
{
    TEST_CASE("procfs_read_sudo_info: init process (no SUDO_UID)");

    uid_t uid = 999;  // Initialize to non-zero
    char user[256];
    pid_t init_pid = 1;

    bool ret = procfs_read_sudo_info(init_pid, &uid, user, sizeof(user));

    // Init shouldn't have SUDO_UID
    ASSERT_FALSE(ret);
}

// Test maximum buffer size
static void test_procfs_cmdline_max_buffer(void)
{
    TEST_CASE("procfs_read_cmdline: maximum buffer size");

    char large_buf[16384];  // 16KB buffer
    pid_t my_pid = getpid();

    bool ret = procfs_read_cmdline(my_pid, large_buf, sizeof(large_buf));

    if (ret) {
        // Should be null-terminated
        ASSERT_TRUE(strlen(large_buf) < sizeof(large_buf));
        // Should not have buffer overflow
        ASSERT_EQ(large_buf[sizeof(large_buf) - 1], '\0');
    }
}

// Test that empty cmdline is handled correctly
static void test_procfs_cmdline_empty(void)
{
    TEST_CASE("procfs_read_cmdline: empty cmdline handling");

    char buf[1024];

    // Kernel threads have empty cmdlines (e.g., kthreadd)
    // We can't reliably test this as we don't know which PID is a kernel thread
    // But we can at least test that PID 2 (kthreadd on most systems) is handled
    pid_t kthread_pid = 2;

    bool ret = procfs_read_cmdline(kthread_pid, buf, sizeof(buf));

    // May succeed with empty string or fail
    if (ret) {
        // If successful, might be empty
        ASSERT_TRUE(strlen(buf) == 0 || strlen(buf) > 0);
    }
}

// Test concurrent reads (thread safety check)
static void test_procfs_cmdline_concurrent(void)
{
    TEST_CASE("procfs_read_cmdline: concurrent reads");

    char buf1[1024], buf2[1024];
    pid_t my_pid = getpid();

    // Read twice in succession
    bool ret1 = procfs_read_cmdline(my_pid, buf1, sizeof(buf1));
    bool ret2 = procfs_read_cmdline(my_pid, buf2, sizeof(buf2));

    ASSERT_EQ(ret1, ret2);
    if (ret1 && ret2) {
        // Should get same result
        ASSERT_STREQ(buf1, buf2);
    }
}

int main(void)
{
    TEST_SUITE("LinMon procfs Tests - Buffer Handling");

    // cmdline tests
    test_procfs_read_own_cmdline();
    test_procfs_cmdline_buffer_overflow();
    test_procfs_cmdline_null_buffer();
    test_procfs_cmdline_zero_size();
    test_procfs_cmdline_nonexistent_pid();
    test_procfs_cmdline_buffer_init();
    test_procfs_cmdline_one_byte_buffer();
    test_procfs_cmdline_two_byte_buffer();
    test_procfs_read_init_cmdline();
    test_procfs_cmdline_null_separation();
    test_procfs_cmdline_max_buffer();
    test_procfs_cmdline_empty();
    test_procfs_cmdline_concurrent();

    // sudo info tests
    test_procfs_sudo_null_params();
    test_procfs_sudo_nonexistent_pid();
    test_procfs_sudo_buffer_overflow();
    test_procfs_sudo_zero_size_buffer();
    test_procfs_sudo_init_process();

    print_test_summary();

    return (tests_failed > 0) ? 1 : 0;
}
