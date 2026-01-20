// SPDX-License-Identifier: GPL-2.0-or-later
// Simple unit test framework for LinMon

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Test statistics
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

// Colors for output
#define COLOR_GREEN  "\033[0;32m"
#define COLOR_RED    "\033[0;31m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_RESET  "\033[0m"

// Test assertion macros
#define ASSERT_TRUE(expr) do { \
    tests_run++; \
    if (expr) { \
        tests_passed++; \
        printf("  " COLOR_GREEN "✓" COLOR_RESET " %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    } else { \
        tests_failed++; \
        printf("  " COLOR_RED "✗" COLOR_RESET " %s:%d: %s (expected true)\n", __FILE__, __LINE__, #expr); \
    } \
} while(0)

#define ASSERT_FALSE(expr) do { \
    tests_run++; \
    if (!(expr)) { \
        tests_passed++; \
        printf("  " COLOR_GREEN "✓" COLOR_RESET " %s:%d: !(%s)\n", __FILE__, __LINE__, #expr); \
    } else { \
        tests_failed++; \
        printf("  " COLOR_RED "✗" COLOR_RESET " %s:%d: %s (expected false)\n", __FILE__, __LINE__, #expr); \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    tests_run++; \
    if ((a) == (b)) { \
        tests_passed++; \
        printf("  " COLOR_GREEN "✓" COLOR_RESET " %s:%d: %s == %s\n", __FILE__, __LINE__, #a, #b); \
    } else { \
        tests_failed++; \
        printf("  " COLOR_RED "✗" COLOR_RESET " %s:%d: %s != %s (%ld != %ld)\n", \
               __FILE__, __LINE__, #a, #b, (long)(a), (long)(b)); \
    } \
} while(0)

#define ASSERT_NEQ(a, b) do { \
    tests_run++; \
    if ((a) != (b)) { \
        tests_passed++; \
        printf("  " COLOR_GREEN "✓" COLOR_RESET " %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b); \
    } else { \
        tests_failed++; \
        printf("  " COLOR_RED "✗" COLOR_RESET " %s:%d: %s == %s (both %ld)\n", \
               __FILE__, __LINE__, #a, #b, (long)(a)); \
    } \
} while(0)

#define ASSERT_STREQ(a, b) do { \
    tests_run++; \
    if ((a) && (b) && strcmp((a), (b)) == 0) { \
        tests_passed++; \
        printf("  " COLOR_GREEN "✓" COLOR_RESET " %s:%d: %s == %s\n", __FILE__, __LINE__, #a, #b); \
    } else { \
        tests_failed++; \
        printf("  " COLOR_RED "✗" COLOR_RESET " %s:%d: %s != %s (\"%s\" != \"%s\")\n", \
               __FILE__, __LINE__, #a, #b, (a) ? (a) : "NULL", (b) ? (b) : "NULL"); \
    } \
} while(0)

#define ASSERT_STRNEQ(a, b) do { \
    tests_run++; \
    if ((a) && (b) && strcmp((a), (b)) != 0) { \
        tests_passed++; \
        printf("  " COLOR_GREEN "✓" COLOR_RESET " %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b); \
    } else { \
        tests_failed++; \
        printf("  " COLOR_RED "✗" COLOR_RESET " %s:%d: %s == %s (\"%s\")\n", \
               __FILE__, __LINE__, #a, #b, (a) ? (a) : "NULL"); \
    } \
} while(0)

#define ASSERT_NULL(ptr) do { \
    tests_run++; \
    if ((ptr) == NULL) { \
        tests_passed++; \
        printf("  " COLOR_GREEN "✓" COLOR_RESET " %s:%d: %s is NULL\n", __FILE__, __LINE__, #ptr); \
    } else { \
        tests_failed++; \
        printf("  " COLOR_RED "✗" COLOR_RESET " %s:%d: %s is not NULL (%p)\n", \
               __FILE__, __LINE__, #ptr, (void*)(ptr)); \
    } \
} while(0)

#define ASSERT_NOT_NULL(ptr) do { \
    tests_run++; \
    if ((ptr) != NULL) { \
        tests_passed++; \
        printf("  " COLOR_GREEN "✓" COLOR_RESET " %s:%d: %s is not NULL\n", __FILE__, __LINE__, #ptr); \
    } else { \
        tests_failed++; \
        printf("  " COLOR_RED "✗" COLOR_RESET " %s:%d: %s is NULL\n", __FILE__, __LINE__, #ptr); \
    } \
} while(0)

// Test suite macros
#define TEST_SUITE(name) \
    printf("\n" COLOR_YELLOW "══════════════════════════════════════════════════" COLOR_RESET "\n"); \
    printf(COLOR_YELLOW "  Test Suite: %s" COLOR_RESET "\n", name); \
    printf(COLOR_YELLOW "══════════════════════════════════════════════════" COLOR_RESET "\n")

#define TEST_CASE(name) \
    printf("\n" COLOR_YELLOW "▶" COLOR_RESET " %s\n", name)

// Summary
static void print_test_summary(void) {
    printf("\n" COLOR_YELLOW "══════════════════════════════════════════════════" COLOR_RESET "\n");
    printf(COLOR_YELLOW "  Test Summary" COLOR_RESET "\n");
    printf(COLOR_YELLOW "══════════════════════════════════════════════════" COLOR_RESET "\n");
    printf("  Total:  %d tests\n", tests_run);
    printf("  " COLOR_GREEN "Passed: %d" COLOR_RESET "\n", tests_passed);
    if (tests_failed > 0) {
        printf("  " COLOR_RED "Failed: %d" COLOR_RESET "\n", tests_failed);
    } else {
        printf("  Failed: 0\n");
    }

    if (tests_failed == 0) {
        printf("\n  " COLOR_GREEN "✓ ALL TESTS PASSED" COLOR_RESET "\n");
    } else {
        printf("\n  " COLOR_RED "✗ SOME TESTS FAILED" COLOR_RESET "\n");
    }
    printf(COLOR_YELLOW "══════════════════════════════════════════════════" COLOR_RESET "\n\n");
}

#endif // TEST_FRAMEWORK_H
