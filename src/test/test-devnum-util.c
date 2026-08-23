/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "devnum-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "tests.h"

TEST(parse_devnum) {
        dev_t dev;

        assert_se(parse_devnum("", &dev) == -EINVAL);
        assert_se(parse_devnum("junk", &dev) == -EINVAL);
        assert_se(parse_devnum("0", &dev) == -EINVAL);
        assert_se(parse_devnum("5", &dev) == -EINVAL);
        assert_se(parse_devnum("5:", &dev) == -EINVAL);
        assert_se(parse_devnum(":5", &dev) == -EINVAL);
        assert_se(parse_devnum("-1:-1", &dev) == -EINVAL);
#if SIZEOF_DEV_T < 8
        assert_se(parse_devnum("4294967295:4294967295", &dev) == -EINVAL);
#endif
        assert_se(parse_devnum("8:11", &dev) >= 0 && major(dev) == 8 && minor(dev) == 11);
        assert_se(parse_devnum("0:0", &dev) >= 0 && major(dev) == 0 && minor(dev) == 0);
}

TEST(device_major_minor_valid) {
        /* on glibc dev_t is 64-bit, even though in the kernel it is only 32-bit */
        assert_cc(sizeof(dev_t) == sizeof(uint64_t));

        assert_se(DEVICE_MAJOR_VALID(0U));
        assert_se(DEVICE_MINOR_VALID(0U));

        assert_se(DEVICE_MAJOR_VALID(1U));
        assert_se(DEVICE_MINOR_VALID(1U));

        assert_se(!DEVICE_MAJOR_VALID(-1U));
        assert_se(!DEVICE_MINOR_VALID(-1U));

        assert_se(DEVICE_MAJOR_VALID(1U << 10));
        assert_se(DEVICE_MINOR_VALID(1U << 10));

        assert_se(DEVICE_MAJOR_VALID((1U << 12) - 1));
        assert_se(DEVICE_MINOR_VALID((1U << 20) - 1));

        assert_se(!DEVICE_MAJOR_VALID((1U << 12)));
        assert_se(!DEVICE_MINOR_VALID((1U << 20)));

        assert_se(!DEVICE_MAJOR_VALID(1U << 25));
        assert_se(!DEVICE_MINOR_VALID(1U << 25));

        assert_se(!DEVICE_MAJOR_VALID(UINT32_MAX));
        assert_se(!DEVICE_MINOR_VALID(UINT32_MAX));

        assert_se(!DEVICE_MAJOR_VALID(UINT64_MAX));
        assert_se(!DEVICE_MINOR_VALID(UINT64_MAX));

        assert_se(DEVICE_MAJOR_VALID(major(0)));
        assert_se(DEVICE_MINOR_VALID(minor(0)));
}

static void test_device_path_make_canonical_one(const char *path) {
        _cleanup_free_ char *resolved = NULL, *raw = NULL;
        struct stat st;
        dev_t devno;
        mode_t mode;
        int r;

        log_debug("> %s", path);

        if (stat(path, &st) < 0) {
                assert_se(errno == ENOENT);
                log_notice("Path %s not found, skipping test", path);
                return;
        }

        r = device_path_make_canonical(st.st_mode, st.st_rdev, &resolved);
        if (r == -ENOENT) {
                /* maybe /dev/char/x:y and /dev/block/x:y are missing in this test environment, because we
                 * run in a container or so? */
                log_notice("Device %s cannot be resolved, skipping test", path);
                return;
        }

        assert_se(r >= 0);
        assert_se(path_equal(path, resolved));

        assert_se(device_path_make_major_minor(st.st_mode, st.st_rdev, &raw) >= 0);
        assert_se(device_path_parse_major_minor(raw, &mode, &devno) >= 0);

        assert_se(st.st_rdev == devno);
        assert_se((st.st_mode & S_IFMT) == (mode & S_IFMT));
}

TEST(device_path_make_canonical) {
        test_device_path_make_canonical_one("/dev/null");
        test_device_path_make_canonical_one("/dev/zero");
        test_device_path_make_canonical_one("/dev/full");
        test_device_path_make_canonical_one("/dev/random");
        test_device_path_make_canonical_one("/dev/urandom");
        test_device_path_make_canonical_one("/dev/tty");

        if (is_device_node("/run/systemd/inaccessible/blk") > 0) {
                test_device_path_make_canonical_one("/run/systemd/inaccessible/chr");
                test_device_path_make_canonical_one("/run/systemd/inaccessible/blk");
        }
}

static void test_devnum_format_str_one(dev_t devnum, const char *s) {
        dev_t x;

        ASSERT_STREQ(FORMAT_DEVNUM(devnum), s);
        assert_se(parse_devnum(s, &x) >= 0);
        assert_se(x == devnum);
}

TEST(devnum_format_str) {
        test_devnum_format_str_one(makedev(0, 0), "0:0");
        test_devnum_format_str_one(makedev(1, 2), "1:2");
        test_devnum_format_str_one(makedev(99, 100), "99:100");
        test_devnum_format_str_one(makedev(4095, 1048575), "4095:1048575");
}

TEST(devnum_to_ptr) {
        dev_t m = makedev(0, 0);
        ASSERT_EQ(major(m), 0U);
        ASSERT_EQ(minor(m), 0U);
        ASSERT_EQ(m, PTR_TO_DEVNUM(DEVNUM_TO_PTR(m)));

        m = makedev(DEVNUM_MAJOR_MAX, DEVNUM_MINOR_MAX);
        ASSERT_EQ(major(m), DEVNUM_MAJOR_MAX);
        ASSERT_EQ(minor(m), DEVNUM_MINOR_MAX);
        ASSERT_EQ(m, PTR_TO_DEVNUM(DEVNUM_TO_PTR(m)));

        m = makedev(5, 8);
        ASSERT_EQ(major(m), 5U);
        ASSERT_EQ(minor(m), 8U);
        ASSERT_EQ(m, PTR_TO_DEVNUM(DEVNUM_TO_PTR(m)));
}

DEFINE_TEST_MAIN(LOG_INFO);
