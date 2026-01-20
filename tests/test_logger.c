// SPDX-License-Identifier: GPL-2.0-or-later
// Unit tests for logger.c - JSON escaping edge cases

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "test_framework.h"

// Copy of json_escape function from logger.c for testing
// (static functions can't be tested directly, so we duplicate for unit tests)
static void json_escape(const char *src, char *dst, size_t dst_size)
{
    size_t j = 0;

    if (!src || !dst || dst_size == 0)
        return;

    for (size_t i = 0; src[i] && j < dst_size - 1; i++) {
        unsigned char c = src[i];

        // Check if we have room for escape sequence
        if (j >= dst_size - 6)
            break;

        switch (c) {
        case '"':
            dst[j++] = '\\';
            dst[j++] = '"';
            break;
        case '\\':
            dst[j++] = '\\';
            dst[j++] = '\\';
            break;
        case '\b':
            dst[j++] = '\\';
            dst[j++] = 'b';
            break;
        case '\f':
            dst[j++] = '\\';
            dst[j++] = 'f';
            break;
        case '\n':
            dst[j++] = '\\';
            dst[j++] = 'n';
            break;
        case '\r':
            dst[j++] = '\\';
            dst[j++] = 'r';
            break;
        case '\t':
            dst[j++] = '\\';
            dst[j++] = 't';
            break;
        default:
            // Control characters - escape as \uXXXX
            if (c < 0x20) {
                // Ensure we have room for full escape sequence
                if (j + 6 >= dst_size)
                    break;
                int written = snprintf(dst + j, dst_size - j, "\\u%04x", c);
                if (written > 0 && written < (int)(dst_size - j))
                    j += written;
                else
                    break;  // snprintf failed or would truncate
            } else {
                dst[j++] = c;
            }
            break;
        }
    }
    dst[j] = '\0';
}

// Test basic quote escaping
static void test_escape_quotes(void)
{
    TEST_CASE("JSON escaping: quotes");

    char dst[256];

    json_escape("simple text", dst, sizeof(dst));
    ASSERT_STREQ(dst, "simple text");

    json_escape("text with \"quotes\"", dst, sizeof(dst));
    ASSERT_STREQ(dst, "text with \\\"quotes\\\"");

    json_escape("\"quoted\"", dst, sizeof(dst));
    ASSERT_STREQ(dst, "\\\"quoted\\\"");
}

// Test backslash escaping
static void test_escape_backslashes(void)
{
    TEST_CASE("JSON escaping: backslashes");

    char dst[256];

    json_escape("path\\to\\file", dst, sizeof(dst));
    ASSERT_STREQ(dst, "path\\\\to\\\\file");

    json_escape("C:\\Windows\\System32", dst, sizeof(dst));
    ASSERT_STREQ(dst, "C:\\\\Windows\\\\System32");

    json_escape("\\\\server\\share", dst, sizeof(dst));
    ASSERT_STREQ(dst, "\\\\\\\\server\\\\share");
}

// Test control character escaping
static void test_escape_control_chars(void)
{
    TEST_CASE("JSON escaping: control characters");

    char dst[256];

    json_escape("line1\nline2", dst, sizeof(dst));
    ASSERT_STREQ(dst, "line1\\nline2");

    json_escape("tab\there", dst, sizeof(dst));
    ASSERT_STREQ(dst, "tab\\there");

    json_escape("carriage\rreturn", dst, sizeof(dst));
    ASSERT_STREQ(dst, "carriage\\rreturn");

    json_escape("backspace\bhere", dst, sizeof(dst));
    ASSERT_STREQ(dst, "backspace\\bhere");

    json_escape("formfeed\fhere", dst, sizeof(dst));
    ASSERT_STREQ(dst, "formfeed\\fhere");
}

// Test Unicode escaping for low control characters
static void test_escape_unicode_control(void)
{
    TEST_CASE("JSON escaping: Unicode control characters");

    char dst[256];
    char input[256];

    // NUL character (0x00) - should stop processing
    input[0] = '\0';
    json_escape(input, dst, sizeof(dst));
    ASSERT_STREQ(dst, "");

    // SOH (0x01)
    snprintf(input, sizeof(input), "text%chere", 0x01);
    json_escape(input, dst, sizeof(dst));
    ASSERT_STREQ(dst, "text\\u0001here");

    // BEL (0x07)
    snprintf(input, sizeof(input), "text%chere", 0x07);
    json_escape(input, dst, sizeof(dst));
    ASSERT_STREQ(dst, "text\\u0007here");

    // VT (0x0B - vertical tab)
    snprintf(input, sizeof(input), "text%chere", 0x0B);
    json_escape(input, dst, sizeof(dst));
    ASSERT_STREQ(dst, "text\\u000bhere");

    // ESC (0x1B)
    snprintf(input, sizeof(input), "text%chere", 0x1B);
    json_escape(input, dst, sizeof(dst));
    ASSERT_STREQ(dst, "text\\u001bhere");
}

// Test mixed special characters
static void test_escape_mixed(void)
{
    TEST_CASE("JSON escaping: mixed special characters");

    char dst[512];

    json_escape("\"path\\to\\file\"\nwith\ttabs", dst, sizeof(dst));
    ASSERT_STREQ(dst, "\\\"path\\\\to\\\\file\\\"\\nwith\\ttabs");

    json_escape("line1\nline2\rline3\tline4", dst, sizeof(dst));
    ASSERT_STREQ(dst, "line1\\nline2\\rline3\\tline4");
}

// Test empty and NULL input
static void test_escape_null_empty(void)
{
    TEST_CASE("JSON escaping: NULL and empty strings");

    char dst[256] = "unchanged";

    // NULL source
    json_escape(NULL, dst, sizeof(dst));
    ASSERT_STREQ(dst, "unchanged");  // Should not modify dst

    // Empty string
    json_escape("", dst, sizeof(dst));
    ASSERT_STREQ(dst, "");

    // NULL destination - should not crash
    json_escape("test", NULL, 0);

    // Zero size - should not crash
    json_escape("test", dst, 0);
}

// Test buffer overflow protection
static void test_escape_buffer_overflow(void)
{
    TEST_CASE("JSON escaping: buffer overflow protection");

    char small_buf[10];

    // Short input that fits
    json_escape("abc", small_buf, sizeof(small_buf));
    ASSERT_STREQ(small_buf, "abc");

    // Input with escapes that would overflow
    json_escape("\"\"\"\"\"\"\"\"\"\"", small_buf, sizeof(small_buf));
    // Should be truncated safely with null terminator
    ASSERT_TRUE(strlen(small_buf) < sizeof(small_buf));
    ASSERT_TRUE(small_buf[sizeof(small_buf) - 1] == '\0');

    // Very long input
    char long_input[1000];
    memset(long_input, 'A', sizeof(long_input) - 1);
    long_input[sizeof(long_input) - 1] = '\0';

    json_escape(long_input, small_buf, sizeof(small_buf));
    ASSERT_TRUE(strlen(small_buf) < sizeof(small_buf));
    ASSERT_TRUE(small_buf[sizeof(small_buf) - 1] == '\0');
}

// Test that normal ASCII characters are not escaped
static void test_escape_normal_ascii(void)
{
    TEST_CASE("JSON escaping: normal ASCII unchanged");

    char dst[256];

    json_escape("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", dst, sizeof(dst));
    ASSERT_STREQ(dst, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

    json_escape("0123456789", dst, sizeof(dst));
    ASSERT_STREQ(dst, "0123456789");

    json_escape("!@#$%^&*()_+-=[]{}|;:',.<>?/", dst, sizeof(dst));
    ASSERT_STREQ(dst, "!@#$%^&*()_+-=[]{}|;:',.<>?/");
}

// Test real-world command lines
static void test_escape_real_world(void)
{
    TEST_CASE("JSON escaping: real-world examples");

    char dst[1024];

    // Shell command with quotes
    json_escape("sh -c \"echo 'hello world'\"", dst, sizeof(dst));
    ASSERT_STREQ(dst, "sh -c \\\"echo 'hello world'\\\"");

    // Python with newlines (from multiline string)
    json_escape("python -c \"import sys\nsys.exit(0)\"", dst, sizeof(dst));
    ASSERT_STREQ(dst, "python -c \\\"import sys\\nsys.exit(0)\\\"");

    // Windows path
    json_escape("C:\\Program Files\\Application\\app.exe", dst, sizeof(dst));
    ASSERT_STREQ(dst, "C:\\\\Program Files\\\\Application\\\\app.exe");

    // Script with tabs and newlines
    json_escape("#!/bin/bash\necho\t\"test\"", dst, sizeof(dst));
    ASSERT_STREQ(dst, "#!/bin/bash\\necho\\t\\\"test\\\"");
}

// Test edge case: just special characters
static void test_escape_only_special(void)
{
    TEST_CASE("JSON escaping: only special characters");

    char dst[256];

    json_escape("\"\"\"\"\n\n\n\n", dst, sizeof(dst));
    ASSERT_STREQ(dst, "\\\"\\\"\\\"\\\"\\n\\n\\n\\n");

    json_escape("\\\\\\\\\t\t\t\t", dst, sizeof(dst));
    ASSERT_STREQ(dst, "\\\\\\\\\\\\\\\\\\t\\t\\t\\t");
}

// Test that we can escape the result of an escape
static void test_escape_double_escape(void)
{
    TEST_CASE("JSON escaping: double escaping");

    char dst1[256];
    char dst2[512];

    // First escape
    json_escape("path\\to\\\"file\"", dst1, sizeof(dst1));
    ASSERT_STREQ(dst1, "path\\\\to\\\\\\\"file\\\"");

    // Second escape (escaping the already-escaped string)
    json_escape(dst1, dst2, sizeof(dst2));
    ASSERT_STREQ(dst2, "path\\\\\\\\to\\\\\\\\\\\\\\\"file\\\\\\\"");
}

// Test boundary: exactly at buffer limit
static void test_escape_exact_buffer_boundary(void)
{
    TEST_CASE("JSON escaping: exact buffer boundary");

    // Buffer that can hold exactly "abc\0" (4 bytes)
    char buf[4];
    json_escape("abc", buf, sizeof(buf));
    ASSERT_STREQ(buf, "abc");

    // Input that would require 4 bytes after escaping: "a\"" -> "a\\\"" (4 bytes + null)
    // Should fit: a\\"
    char buf2[5];
    json_escape("a\"", buf2, sizeof(buf2));
    ASSERT_STREQ(buf2, "a\\\"");

    // Input that wouldn't fit: "\"\"" -> "\\\"\\\""  (6 bytes + null = 7)
    // Buffer is only 5, so should truncate safely
    char buf3[5];
    json_escape("\"\"", buf3, sizeof(buf3));
    ASSERT_TRUE(strlen(buf3) < sizeof(buf3));
    ASSERT_EQ(buf3[sizeof(buf3) - 1], '\0');
}

// Test high-bit characters (0x80-0xFF) - should pass through
static void test_escape_high_bit_chars(void)
{
    TEST_CASE("JSON escaping: high-bit characters");

    char dst[256];
    unsigned char input[256];

    // Test 0x80
    input[0] = 0x80;
    input[1] = '\0';
    json_escape((char *)input, dst, sizeof(dst));
    ASSERT_EQ((unsigned char)dst[0], 0x80);
    ASSERT_EQ(dst[1], '\0');

    // Test 0xFF
    input[0] = 0xFF;
    input[1] = '\0';
    json_escape((char *)input, dst, sizeof(dst));
    ASSERT_EQ((unsigned char)dst[0], 0xFF);
    ASSERT_EQ(dst[1], '\0');

    // Test mixed high-bit (UTF-8 like sequence)
    input[0] = 0xC3;
    input[1] = 0xA9;  // é in UTF-8
    input[2] = '\0';
    json_escape((char *)input, dst, sizeof(dst));
    ASSERT_EQ((unsigned char)dst[0], 0xC3);
    ASSERT_EQ((unsigned char)dst[1], 0xA9);
    ASSERT_EQ(dst[2], '\0');
}

int main(void)
{
    TEST_SUITE("LinMon Logger Tests - JSON Escaping");

    test_escape_quotes();
    test_escape_backslashes();
    test_escape_control_chars();
    test_escape_unicode_control();
    test_escape_mixed();
    test_escape_null_empty();
    test_escape_buffer_overflow();
    test_escape_normal_ascii();
    test_escape_real_world();
    test_escape_only_special();
    test_escape_double_escape();
    test_escape_exact_buffer_boundary();
    test_escape_high_bit_chars();

    print_test_summary();

    return (tests_failed > 0) ? 1 : 0;
}
