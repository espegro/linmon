// SPDX-License-Identifier: GPL-2.0-or-later
// Unit tests for utils.c - Safe file operations

#include "test_framework.h"
#include "../src/utils.h"
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

static void test_safe_fopen_create_regular_file(void) {
    TEST_CASE("safe_fopen: create regular file");

    const char *path = "/tmp/linmon_test_regular.txt";

    // Clean up from previous test
    unlink(path);

    // Open file for writing
    FILE *fp = safe_fopen(path, "w", 0600);
    ASSERT_TRUE(fp != NULL);

    fprintf(fp, "test content\n");
    fclose(fp);

    // Verify file was created with correct permissions
    struct stat st;
    ASSERT_EQ(stat(path, &st), 0);
    ASSERT_EQ(st.st_mode & 0777, 0600);

    // Clean up
    unlink(path);
}

static void test_safe_fopen_append_mode(void) {
    TEST_CASE("safe_fopen: append mode");

    const char *path = "/tmp/linmon_test_append.txt";

    // Clean up from previous test
    unlink(path);

    // Create initial file
    FILE *fp1 = safe_fopen(path, "w", 0640);
    ASSERT_TRUE(fp1 != NULL);
    fprintf(fp1, "line1\n");
    fclose(fp1);

    // Append to file
    FILE *fp2 = safe_fopen(path, "a", 0640);
    ASSERT_TRUE(fp2 != NULL);
    fprintf(fp2, "line2\n");
    fclose(fp2);

    // Verify both lines present
    FILE *fp3 = fopen(path, "r");
    char buf[100];
    char *ret1 = fgets(buf, sizeof(buf), fp3);
    ASSERT_TRUE(ret1 != NULL);
    ASSERT_STREQ(buf, "line1\n");
    char *ret2 = fgets(buf, sizeof(buf), fp3);
    ASSERT_TRUE(ret2 != NULL);
    ASSERT_STREQ(buf, "line2\n");
    fclose(fp3);

    // Clean up
    unlink(path);
}

static void test_safe_fopen_read_mode(void) {
    TEST_CASE("safe_fopen: read mode");

    const char *path = "/tmp/linmon_test_read.txt";

    // Clean up from previous test
    unlink(path);

    // Create file with fopen first
    FILE *fp1 = fopen(path, "w");
    ASSERT_TRUE(fp1 != NULL);
    fprintf(fp1, "test content\n");
    fclose(fp1);

    // Open for reading with safe_fopen
    FILE *fp2 = safe_fopen(path, "r", 0);  // perms ignored for read mode
    ASSERT_TRUE(fp2 != NULL);

    // Verify can read content
    char buf[100];
    char *ret = fgets(buf, sizeof(buf), fp2);
    ASSERT_TRUE(ret != NULL);
    ASSERT_STREQ(buf, "test content\n");
    fclose(fp2);

    // Clean up
    unlink(path);
}

static void test_safe_fopen_rejects_symlink(void) {
    TEST_CASE("safe_fopen: rejects symlink (ELOOP)");

    const char *target = "/tmp/linmon_test_target.txt";
    const char *link = "/tmp/linmon_test_symlink.txt";

    // Clean up from previous test
    unlink(target);
    unlink(link);

    // Create target file
    FILE *fp_target = fopen(target, "w");
    fprintf(fp_target, "target content\n");
    fclose(fp_target);

    // Create symlink
    ASSERT_EQ(symlink(target, link), 0);

    // Attempt to open symlink - should fail with ELOOP
    errno = 0;
    FILE *fp = safe_fopen(link, "a", 0640);
    ASSERT_TRUE(fp == NULL);
    ASSERT_EQ(errno, ELOOP);

    // Clean up
    unlink(link);
    unlink(target);
}

static void test_safe_fopen_invalid_mode(void) {
    TEST_CASE("safe_fopen: invalid mode (EINVAL)");

    const char *path = "/tmp/linmon_test_invalid.txt";

    // Invalid mode should fail with EINVAL
    errno = 0;
    FILE *fp = safe_fopen(path, "x", 0600);
    ASSERT_TRUE(fp == NULL);
    ASSERT_EQ(errno, EINVAL);
}

int main(void) {
    TEST_SUITE("LinMon utils Tests - Safe File Operations");

    test_safe_fopen_create_regular_file();
    test_safe_fopen_append_mode();
    test_safe_fopen_read_mode();
    test_safe_fopen_rejects_symlink();
    test_safe_fopen_invalid_mode();

    print_test_summary();

    return (tests_failed > 0) ? 1 : 0;
}
