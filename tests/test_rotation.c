// Exercise the production logger, including a failed replacement-file open.
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include "test_framework.h"
#include "logger.h"

static const char *fail_path;
static bool fail_open;
int __real_open(const char *, int, ...);
int __wrap_open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    if (fail_open && (flags & O_CREAT) && strcmp(path, fail_path) == 0) {
        fail_open = false;
        errno = ENOSPC;
        return -1;
    }
    return __real_open(path, flags, mode);
}

static int check_lines(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    int count = 0;
    while ((length = getline(&line, &capacity, fp)) > 0) {
        ASSERT_TRUE(length > 2 && line[0] == '{' && line[length - 2] == '}');
        count++;
    }
    free(line);
    fclose(fp);
    return count;
}

int main(void)
{
    TEST_SUITE("Production logger rotation");
    char dir[] = "/tmp/linmon-rotation-XXXXXX";
    ASSERT_TRUE(mkdtemp(dir) != NULL);
    char path[256], rotated[260];
    snprintf(path, sizeof(path), "%s/events.json", dir);
    snprintf(rotated, sizeof(rotated), "%s.1", path);
    ASSERT_EQ(logger_init(path), 0);
    logger_set_rotation(path, true, 4096, 1);
    fail_path = path;
    fail_open = true;
    struct process_event event = {.type = EVENT_PROCESS_EXEC, .pid = 123};
    strcpy(event.comm, "test");
    for (int i = 0; i < 100 && fail_open; i++)
        ASSERT_EQ(logger_log_process_event(&event), 0);
    ASSERT_FALSE(fail_open);
    ASSERT_TRUE(logger_get_fp() != NULL);
    int before = check_lines(path);
    ASSERT_EQ(logger_log_process_event(&event), 0);
    ASSERT_EQ(check_lines(path), before + 1);
    // Retry must eventually rotate successfully, with complete records.
    for (int i = 0; i < 30; i++)
        ASSERT_EQ(logger_log_process_event(&event), 0);
    ASSERT_TRUE(access(rotated, F_OK) == 0);
    ASSERT_TRUE(check_lines(rotated) > 0);
    ASSERT_TRUE(check_lines(path) > 0);
    FILE *full = fopen("/dev/full", "w");
    ASSERT_TRUE(full != NULL);
    if (full) {
        setvbuf(full, NULL, _IONBF, 0);
        logger_replace(full);
        ASSERT_EQ(logger_log_process_event(&event), -EIO);
        FILE *recovered = logger_open_file_secure(path);
        ASSERT_TRUE(recovered != NULL);
        logger_replace(recovered);
        ASSERT_EQ(logger_log_process_event(&event), 0);
    }
    logger_cleanup();
    unlink(path);
    unlink(rotated);
    rmdir(dir);
    print_test_summary();
    return tests_failed ? 1 : 0;
}
