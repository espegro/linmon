# LinMon Unit Tests

Comprehensive unit test suite for LinMon's critical components, covering security-sensitive functionality like credential redaction, buffer handling, and configuration validation.

## Running Tests

### Run All Tests

```bash
make test
```

This will:
1. Compile all test binaries
2. Run each test suite in sequence
3. Report results with colored output
4. Exit with code 0 if all pass, 1 if any fail

### Run Individual Tests

```bash
# Filter tests (redaction, process/file filtering)
./build/tests/test_filter

# Logger tests (JSON escaping)
./build/tests/test_logger

# Config tests (parsing, validation, security checks)
./build/tests/test_config

# Procfs tests (buffer handling, edge cases)
./build/tests/test_procfs
```

## Test Coverage

### test_filter.c (66 tests)
Tests the event filtering and sensitive data redaction system.

**Redaction Tests:**
- Equals format: `password=secret` → `password=******`
- Space-separated: `--password secret` → `--password ******`
- Short options: `-psecret` → `-p******`
- Quoted values: Handles `"value"` and `'value'`
- Multiple occurrences in same command line
- Edge cases: Empty values, special characters
- All 20 sensitive patterns (password, token, api_key, etc.)

**Process Filtering Tests:**
- Whitelist mode (only_processes)
- Blacklist mode (ignore_processes)
- Whitespace handling in config
- NULL pointer safety

**File Path Filtering Tests:**
- Prefix matching (/proc, /sys, /dev)
- Partial prefix edge cases
- NULL and empty string handling

### test_logger.c (47 tests)
Tests JSON escaping for safe event logging.

**Escape Tests:**
- Special characters: `"`, `\`, `\b`, `\f`, `\n`, `\r`, `\t`
- Control characters (< 0x20): Escaped as `\uXXXX`
- Mixed content with multiple escape types
- Real-world command lines (shell, Python, Windows paths)

**Buffer Safety Tests:**
- NULL pointer handling
- Zero-size buffers
- Small buffer truncation
- Exact boundary conditions
- Very large buffers (16KB)

**Edge Cases:**
- Empty strings
- Only special characters
- Double escaping
- High-bit characters (UTF-8 pass-through)

### test_config.c (86 tests)
Tests configuration file parsing and validation.

**Parsing Tests:**
- Boolean values (true/false)
- Integer ranges with validation
- Size parsing with K/M/G suffixes
- String lists (comma-separated)
- Comments and empty lines
- Malformed lines (skipped gracefully)

**Validation Tests:**
- Path security: Must be absolute, no `..`
- UID range bounds checking
- Verbosity limits (0-2)
- Log rotation size/count limits
- Cache size limits

**Security Tests:**
- World-writable config file rejected (-EPERM)
- Non-root ownership warnings
- Group-writable warnings

**Feature Coverage:**
- All monitoring options (processes, network, security)
- Cache configuration
- Security monitoring flags (14 MITRE ATT&CK techniques)

### test_procfs.c (53 tests)
Tests /proc filesystem reading with focus on buffer safety.

**cmdline Tests:**
- Reading current process (always exists)
- Reading init (PID 1)
- Non-existent PID handling
- NULL buffer safety
- Zero-size buffer
- 1-byte and 2-byte edge cases (underflow guard)
- Null-separated argument handling
- Trailing space trimming
- Concurrent reads (idempotency)

**sudo_info Tests:**
- NULL parameter safety
- Non-existent PID
- Buffer overflow protection
- Zero-size buffer handling
- Processes without SUDO_UID

## Test Framework

### Simple C Test Framework

All tests use the lightweight framework in `tests/test_framework.h`:

```c
TEST_SUITE("Test Suite Name");
TEST_CASE("Specific test case");

// Assertions
ASSERT_TRUE(expr);
ASSERT_FALSE(expr);
ASSERT_EQ(a, b);
ASSERT_NEQ(a, b);
ASSERT_STREQ(str1, str2);
ASSERT_STRNEQ(str1, str2);
ASSERT_NULL(ptr);
ASSERT_NOT_NULL(ptr);

print_test_summary();  // At end of main()
```

**Features:**
- Colored output (green ✓ / red ✗)
- Automatic test counting
- Pass/fail summary
- No external dependencies
- Exit code 0 (pass) or 1 (fail)

## Test Statistics

**Total**: 266 tests across 4 test suites
- test_filter: 66 tests
- test_logger: 47 tests
- test_config: 86 tests
- test_procfs: 53 tests

**Completion Status**: ✅ All tests passing

## Adding New Tests

See the full README for detailed instructions on adding new tests, test guidelines, CI/CD integration, and debugging tips.
