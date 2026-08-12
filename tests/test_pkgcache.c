// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <unistd.h>
#include "test_framework.h"
#include "pkgcache.h"

static void test_system_binary_integrity(void)
{
    TEST_CASE("Package cache: verifies a package-owned system binary");
    char cache_path[] = "/tmp/linmon-pkgcache-test-XXXXXX";
    int fd = mkstemp(cache_path);
    ASSERT_TRUE(fd >= 0);
    if (fd >= 0)
        close(fd);
    unlink(cache_path);

    ASSERT_EQ(pkgcache_init(cache_path, 32), 0);
    struct pkg_info info = {0};
    ASSERT_EQ(pkgcache_lookup("/bin/ls", &info), 0);
    ASSERT_TRUE(info.from_package);
    ASSERT_TRUE(info.package[0] != '\0');
    ASSERT_EQ(info.integrity, PKG_INTEGRITY_VERIFIED);
    ASSERT_FALSE(info.modified);

    ASSERT_EQ(pkgcache_verify("/bin/ls", &info), 0);
    ASSERT_EQ(info.integrity, PKG_INTEGRITY_VERIFIED);

    pkgcache_cleanup();
    unlink(cache_path);
}

int main(void)
{
    TEST_SUITE("LinMon Package Integrity Tests");
    test_system_binary_integrity();
    print_test_summary();
    return tests_failed > 0 ? 1 : 0;
}
