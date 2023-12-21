/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-util.h"
#include "mountpoint-util.h"
#include "tests.h"

TEST(log_device_full) {
        int r;

        for (int level = LOG_ERR; level <= LOG_DEBUG; level++) {
                log_device_full(NULL, level, "test level=%d: %m", level);

                r = log_device_full_errno(NULL, level, EUCLEAN, "test level=%d errno=EUCLEAN: %m", level);
                assert_se(r == -EUCLEAN);

                r = log_device_full_errno(NULL, level, 0, "test level=%d errno=0: %m", level);
                assert_se(r == 0);

                r = log_device_full_errno(NULL, level, SYNTHETIC_ERRNO(ENODATA), "test level=%d errno=S(ENODATA): %m", level);
                assert_se(r == -ENODATA);
        }
}

TEST(device_in_subsystem) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        int r;

        if (path_is_mount_point("/sys", NULL, 0) <= 0)
                return (void) log_tests_skipped("/sys is not mounted");

        r = sd_device_new_from_subsystem_sysname(&dev, "net", "lo");
        if (r == -ENODEV)
                return (void) log_tests_skipped("net/lo does not exist");
        assert_se(r >= 0);

        assert_se(device_in_subsystem(dev, "net"));
        assert_se(!device_in_subsystem(dev, "disk"));
        assert_se(!device_in_subsystem(dev, "subsystem"));
        assert_se(!device_in_subsystem(dev, ""));
        assert_se(!device_in_subsystem(dev, NULL));

        dev = sd_device_unref(dev);

        assert_se(sd_device_new_from_syspath(&dev, "/sys/class/net") >= 0);
        assert_se(!device_in_subsystem(dev, "net"));
        assert_se(!device_in_subsystem(dev, "disk"));
        assert_se(device_in_subsystem(dev, "subsystem"));
        assert_se(!device_in_subsystem(dev, ""));
        assert_se(!device_in_subsystem(dev, NULL));

        dev = sd_device_unref(dev);

        assert_se(sd_device_new_from_syspath(&dev, "/sys/class") >= 0);
        assert_se(!device_in_subsystem(dev, "net"));
        assert_se(!device_in_subsystem(dev, "disk"));
        assert_se(!device_in_subsystem(dev, "subsystem"));
        assert_se(!device_in_subsystem(dev, ""));
        assert_se(device_in_subsystem(dev, NULL));
}

DEFINE_TEST_MAIN(LOG_INFO);
