// SPDX-License-Identifier: GPL-2.0-or-later
// Unit tests for filter.c - Credential redaction and process filtering

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "test_framework.h"
#include "../src/filter.h"
#include "../src/config.h"

// Helper to create minimal config for testing
static struct linmon_config create_test_config(void)
{
    struct linmon_config config = {0};
    config.redact_sensitive = true;
    return config;
}

// Test redaction of password=value format
static void test_redact_equals_format(void)
{
    TEST_CASE("Redaction: equals format (password=secret)");

    char cmdline1[256];
    strcpy(cmdline1, "mysql -u root password=secret123");
    filter_redact_cmdline(cmdline1, sizeof(cmdline1));
    ASSERT_STREQ(cmdline1, "mysql -u root password=*********");  // 9 chars in "secret123"

    char cmdline2[256];
    strcpy(cmdline2, "curl --api-key=abcd1234 https://api.example.com");
    filter_redact_cmdline(cmdline2, sizeof(cmdline2));
    ASSERT_STREQ(cmdline2, "curl --api-key=******** https://api.example.com");

    char cmdline3[256];
    strcpy(cmdline3, "app token=xyz auth=abc");
    filter_redact_cmdline(cmdline3, sizeof(cmdline3));
    ASSERT_STREQ(cmdline3, "app token=*** auth=***");
}

// Test redaction of space-separated values
static void test_redact_space_separated(void)
{
    TEST_CASE("Redaction: space-separated (--password secret)");

    char cmdline1[256];
    strcpy(cmdline1, "mysql --password secret123 -u root");
    filter_redact_cmdline(cmdline1, sizeof(cmdline1));
    ASSERT_STREQ(cmdline1, "mysql --password ********* -u root");

    char cmdline2[256];
    strcpy(cmdline2, "app --token mytoken --api-key mykey");
    filter_redact_cmdline(cmdline2, sizeof(cmdline2));
    ASSERT_STREQ(cmdline2, "app --token ******* --api-key *****");

    // Test short option -p with space
    char cmdline3[256];
    strcpy(cmdline3, "mysql -p secret -u root");
    filter_redact_cmdline(cmdline3, sizeof(cmdline3));
    ASSERT_STREQ(cmdline3, "mysql -p ****** -u root");
}

// Test redaction of short option without space
static void test_redact_short_option_no_space(void)
{
    TEST_CASE("Redaction: short option without space (-psecret)");

    char cmdline1[256];
    strcpy(cmdline1, "mysql -psecret123 -u root");
    filter_redact_cmdline(cmdline1, sizeof(cmdline1));
    ASSERT_STREQ(cmdline1, "mysql -p********* -u root");

    char cmdline2[256];
    strcpy(cmdline2, "mysqldump -pMyP@ssw0rd database");
    filter_redact_cmdline(cmdline2, sizeof(cmdline2));
    ASSERT_STREQ(cmdline2, "mysqldump -p********** database");
}

// Test redaction of quoted values
static void test_redact_quoted_values(void)
{
    TEST_CASE("Redaction: quoted values (--token=\"secret with spaces\")");

    char cmdline1[256];
    strcpy(cmdline1, "curl --api-key=\"my secret key\" https://api.example.com");
    filter_redact_cmdline(cmdline1, sizeof(cmdline1));
    // Opening quote is redacted along with content (15 chars total)
    ASSERT_TRUE(strstr(cmdline1, "curl --api-key=") != NULL);
    ASSERT_TRUE(strstr(cmdline1, "***") != NULL);  // Has asterisks
    ASSERT_TRUE(strstr(cmdline1, "https://api.example.com") != NULL);

    char cmdline2[256];
    strcpy(cmdline2, "app password='complex pass'");
    filter_redact_cmdline(cmdline2, sizeof(cmdline2));
    // Opening quote is redacted, closing quote may remain
    ASSERT_TRUE(strstr(cmdline2, "app password=") != NULL);
    ASSERT_TRUE(strstr(cmdline2, "***") != NULL);  // Has asterisks

    char cmdline3[256];
    strcpy(cmdline3, "app --password \"my pass\" --user admin");
    filter_redact_cmdline(cmdline3, sizeof(cmdline3));
    // Opening quote is redacted along with content
    ASSERT_TRUE(strstr(cmdline3, "app --password ") != NULL);
    ASSERT_TRUE(strstr(cmdline3, "***") != NULL);  // Has asterisks
    ASSERT_TRUE(strstr(cmdline3, "--user admin") != NULL);
}

// Test multiple occurrences of sensitive patterns
static void test_redact_multiple_occurrences(void)
{
    TEST_CASE("Redaction: multiple occurrences");

    char cmdline1[256];
    strcpy(cmdline1, "app password=pass1 token=token1 password=pass2");
    filter_redact_cmdline(cmdline1, sizeof(cmdline1));
    ASSERT_STREQ(cmdline1, "app password=***** token=****** password=*****");

    char cmdline2[256];
    strcpy(cmdline2, "mysql -psecret1 --password secret2");
    filter_redact_cmdline(cmdline2, sizeof(cmdline2));
    ASSERT_STREQ(cmdline2, "mysql -p******* --password *******");
}

// Test edge cases for redaction
static void test_redact_edge_cases(void)
{
    TEST_CASE("Redaction: edge cases");

    // Empty value
    char cmdline1[256];
    strcpy(cmdline1, "app password=");
    filter_redact_cmdline(cmdline1, sizeof(cmdline1));
    ASSERT_STREQ(cmdline1, "app password=");

    // No value after space-separated option
    char cmdline2[256];
    strcpy(cmdline2, "app --password");
    filter_redact_cmdline(cmdline2, sizeof(cmdline2));
    ASSERT_STREQ(cmdline2, "app --password");

    // Another option immediately after
    char cmdline3[256];
    strcpy(cmdline3, "app --password --user admin");
    filter_redact_cmdline(cmdline3, sizeof(cmdline3));
    ASSERT_STREQ(cmdline3, "app --password --user admin");

    // Special characters in password
    char cmdline4[256];
    strcpy(cmdline4, "app password=P@$$w0rd!");
    filter_redact_cmdline(cmdline4, sizeof(cmdline4));
    ASSERT_STREQ(cmdline4, "app password=*********");
}

// Test that redaction respects enabled/disabled setting
static void test_redact_disabled(void)
{
    TEST_CASE("Redaction: disabled via config");

    struct linmon_config config = create_test_config();
    config.redact_sensitive = false;
    filter_init(&config);

    char cmdline[256];
    strcpy(cmdline, "mysql password=secret123");
    filter_redact_cmdline(cmdline, sizeof(cmdline));
    ASSERT_STREQ(cmdline, "mysql password=secret123");  // Not redacted

    // Re-enable for other tests
    config.redact_sensitive = true;
    filter_init(&config);
}

// Test NULL and empty string handling
static void test_redact_null_handling(void)
{
    TEST_CASE("Redaction: NULL and empty handling");

    // NULL pointer (should not crash)
    filter_redact_cmdline(NULL, 0);

    // Empty string
    char cmdline[256] = "";
    filter_redact_cmdline(cmdline, sizeof(cmdline));
    ASSERT_STREQ(cmdline, "");
}

// Test process whitelist filtering
static void test_process_whitelist(void)
{
    TEST_CASE("Process filtering: whitelist (only_processes)");

    struct linmon_config config = create_test_config();
    config.only_processes = strdup("bash,python,ssh");
    filter_init(&config);

    ASSERT_TRUE(filter_should_log_process("bash"));
    ASSERT_TRUE(filter_should_log_process("python"));
    ASSERT_TRUE(filter_should_log_process("ssh"));
    ASSERT_FALSE(filter_should_log_process("curl"));
    ASSERT_FALSE(filter_should_log_process("wget"));

    free(config.only_processes);
}

// Test process blacklist filtering
static void test_process_blacklist(void)
{
    TEST_CASE("Process filtering: blacklist (ignore_processes)");

    struct linmon_config config = create_test_config();
    config.only_processes = NULL;
    config.ignore_processes = strdup("systemd,dbus-daemon,kworker");
    filter_init(&config);

    ASSERT_FALSE(filter_should_log_process("systemd"));
    ASSERT_FALSE(filter_should_log_process("dbus-daemon"));
    ASSERT_FALSE(filter_should_log_process("kworker"));
    ASSERT_TRUE(filter_should_log_process("bash"));
    ASSERT_TRUE(filter_should_log_process("python"));

    free(config.ignore_processes);
}

// Test process filtering with whitespace
static void test_process_whitespace_handling(void)
{
    TEST_CASE("Process filtering: whitespace handling");

    struct linmon_config config = create_test_config();
    config.ignore_processes = strdup("  bash  ,  python  , ssh ");
    filter_init(&config);

    ASSERT_FALSE(filter_should_log_process("bash"));
    ASSERT_FALSE(filter_should_log_process("python"));
    ASSERT_FALSE(filter_should_log_process("ssh"));

    free(config.ignore_processes);
}

// Test process filtering NULL handling
static void test_process_null_handling(void)
{
    TEST_CASE("Process filtering: NULL handling");

    struct linmon_config config = create_test_config();
    filter_init(&config);

    ASSERT_FALSE(filter_should_log_process(NULL));
}

// Test file path prefix filtering
static void test_file_path_filtering(void)
{
    TEST_CASE("File path filtering: prefix matching");

    struct linmon_config config = create_test_config();
    config.ignore_file_paths = strdup("/proc,/sys,/dev");
    filter_init(&config);

    ASSERT_FALSE(filter_should_log_file("/proc/self/maps"));
    ASSERT_FALSE(filter_should_log_file("/proc/1/status"));
    ASSERT_FALSE(filter_should_log_file("/sys/kernel/debug/tracing"));
    ASSERT_FALSE(filter_should_log_file("/dev/null"));
    ASSERT_TRUE(filter_should_log_file("/etc/passwd"));
    ASSERT_TRUE(filter_should_log_file("/home/user/file.txt"));
    ASSERT_TRUE(filter_should_log_file("/var/log/syslog"));

    free(config.ignore_file_paths);
}

// Test file path partial prefix matching
static void test_file_path_partial_match(void)
{
    TEST_CASE("File path filtering: partial prefix");

    struct linmon_config config = create_test_config();
    config.ignore_file_paths = strdup("/tmp");
    filter_init(&config);

    ASSERT_FALSE(filter_should_log_file("/tmp/file.txt"));
    ASSERT_FALSE(filter_should_log_file("/tmp/subdir/file"));
    ASSERT_FALSE(filter_should_log_file("/tmp"));  // Exact prefix match - filtered
    ASSERT_FALSE(filter_should_log_file("/tmpfile"));  // Starts with /tmp prefix - filtered

    free(config.ignore_file_paths);
}

// Test file path NULL and empty handling
static void test_file_path_null_handling(void)
{
    TEST_CASE("File path filtering: NULL and empty handling");

    struct linmon_config config = create_test_config();
    filter_init(&config);

    ASSERT_FALSE(filter_should_log_file(NULL));
    ASSERT_FALSE(filter_should_log_file(""));
}

// Test all patterns are recognized
static void test_all_sensitive_patterns(void)
{
    TEST_CASE("Redaction: all sensitive patterns");

    const char *patterns[] = {
        "password", "passwd", "pwd", "pass", "token", "api_key", "api-key",
        "apikey", "secret", "auth", "auth_token", "auth-token",
        "access_token", "access-token", "client_secret", "client-secret",
        "private_key", "private-key", "credential", "credentials", NULL
    };

    for (int i = 0; patterns[i] != NULL; i++) {
        char cmdline[256];
        snprintf(cmdline, sizeof(cmdline), "app %s=secretvalue", patterns[i]);
        filter_redact_cmdline(cmdline, sizeof(cmdline));

        // Should be redacted
        char expected[256];
        snprintf(expected, sizeof(expected), "app %s=***********", patterns[i]);
        ASSERT_STREQ(cmdline, expected);
    }
}

int main(void)
{
    TEST_SUITE("LinMon Filter Tests");

    // Initialize with default config
    struct linmon_config config = create_test_config();
    filter_init(&config);

    // Redaction tests
    test_redact_equals_format();
    test_redact_space_separated();
    test_redact_short_option_no_space();
    test_redact_quoted_values();
    test_redact_multiple_occurrences();
    test_redact_edge_cases();
    test_redact_disabled();
    test_redact_null_handling();
    test_all_sensitive_patterns();

    // Process filtering tests
    test_process_whitelist();
    test_process_blacklist();
    test_process_whitespace_handling();
    test_process_null_handling();

    // File path filtering tests
    test_file_path_filtering();
    test_file_path_partial_match();
    test_file_path_null_handling();

    print_test_summary();

    return (tests_failed > 0) ? 1 : 0;
}
