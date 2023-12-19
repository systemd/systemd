/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "mountpoint-util.h"
#include "string-util.h"
#include "tests.h"
#include "udev-format.h"

static void test_udev_resolve_subsys_kernel_one(const char *str, bool read_value, int retval, const char *expected) {
        char result[PATH_MAX] = "";
        int r;

        r = udev_resolve_subsys_kernel(str, result, sizeof(result), read_value);
        log_info("\"%s\" → expect: \"%s\", %d, actual: \"%s\", %d", str, strnull(expected), retval, result, r);
        assert_se(r == retval);
        if (r >= 0)
                assert_se(streq(result, expected));
}

TEST(udev_resolve_subsys_kernel) {
        test_udev_resolve_subsys_kernel_one("hoge", false, -EINVAL, NULL);
        test_udev_resolve_subsys_kernel_one("[hoge", false, -EINVAL, NULL);
        test_udev_resolve_subsys_kernel_one("[hoge/foo", false, -EINVAL, NULL);
        test_udev_resolve_subsys_kernel_one("[hoge/]", false, -EINVAL, NULL);

        test_udev_resolve_subsys_kernel_one("[net/lo]", false, 0, "/sys/devices/virtual/net/lo");
        test_udev_resolve_subsys_kernel_one("[net/lo]/", false, 0, "/sys/devices/virtual/net/lo");
        test_udev_resolve_subsys_kernel_one("[net/lo]hoge", false, 0, "/sys/devices/virtual/net/lo/hoge");
        test_udev_resolve_subsys_kernel_one("[net/lo]/hoge", false, 0, "/sys/devices/virtual/net/lo/hoge");

        test_udev_resolve_subsys_kernel_one("[net/lo]", true, -EINVAL, NULL);
        test_udev_resolve_subsys_kernel_one("[net/lo]/", true, -EINVAL, NULL);
        test_udev_resolve_subsys_kernel_one("[net/lo]hoge", true, 0, "");
        test_udev_resolve_subsys_kernel_one("[net/lo]/hoge", true, 0, "");
        test_udev_resolve_subsys_kernel_one("[net/lo]address", true, 0, "00:00:00:00:00:00");
        test_udev_resolve_subsys_kernel_one("[net/lo]/address", true, 0, "00:00:00:00:00:00");
}

static int intro(void) {
        if (path_is_mount_point("/sys", NULL, 0) <= 0)
                return log_tests_skipped("/sys is not mounted");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
