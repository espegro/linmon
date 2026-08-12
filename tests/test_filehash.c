// SPDX-License-Identifier: GPL-2.0-or-later
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "test_framework.h"
#include "filehash.h"

static void test_preopened_descriptor_hashing(void)
{
    TEST_CASE("File hash: pre-opened descriptor survives permission removal");
    char path[] = "/tmp/linmon-filehash-data-XXXXXX";
    char cache[] = "/tmp/linmon-filehash-cache-XXXXXX";
    char before[SHA256_HEX_LEN], after[SHA256_HEX_LEN];
    struct stat original_st;
    struct timespec times[2];
    int fd = mkstemp(path);
    int cache_fd = mkstemp(cache);

    ASSERT_TRUE(fd >= 0);
    ASSERT_TRUE(cache_fd >= 0);
    if (fd < 0 || cache_fd < 0)
        return;
    close(cache_fd);
    unlink(cache);
    ASSERT_EQ(filehash_init(cache, 16), 0);

    ASSERT_EQ(write(fd, "original", 8), 8);
    ASSERT_EQ(fsync(fd), 0);
    ASSERT_EQ(fstat(fd, &original_st), 0);
    times[0] = original_st.st_atim;
    times[1] = original_st.st_mtim;

    ASSERT_EQ(lseek(fd, 3, SEEK_SET), 3);
    ASSERT_TRUE(filehash_calculate_fd(fd, path, before, sizeof(before)));
    ASSERT_EQ(lseek(fd, 0, SEEK_CUR), 3);

    ASSERT_EQ(fchmod(fd, 0000), 0);
    ASSERT_EQ(open(path, O_RDONLY), -1);
    ASSERT_TRUE(filehash_calculate_fd(fd, path, after, sizeof(after)));
    ASSERT_TRUE(strcmp(before, after) == 0);

    // Same inode, size and restored mtime must still be detected because the
    // descriptor API always reads content instead of trusting cache metadata.
    ASSERT_EQ(pwrite(fd, "tampered", 8, 0), 8);
    ASSERT_EQ(fsync(fd), 0);
    ASSERT_EQ(futimens(fd, times), 0);
    ASSERT_TRUE(filehash_calculate_fd(fd, path, after, sizeof(after)));
    ASSERT_TRUE(strcmp(before, after) != 0);

    filehash_cleanup();
    close(fd);
    unlink(path);
    unlink(cache);
}

int main(void)
{
    TEST_SUITE("LinMon File Hash Descriptor Tests");
    test_preopened_descriptor_hashing();
    print_test_summary();
    return tests_failed > 0 ? 1 : 0;
}
