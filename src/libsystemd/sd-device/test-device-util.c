/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-util.h"
#include "mountpoint-util.h"
#include "tests.h"

TEST(log_device_full) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

        (void) sd_device_new_from_subsystem_sysname(&dev, "net", "lo");

        for (int level = LOG_ERR; level <= LOG_DEBUG; level++) {
                log_device_full(dev, level, "test level=%d: %m", level);

                ASSERT_EQ(log_device_full_errno(dev, level, EUCLEAN, "test level=%d errno=EUCLEAN: %m", level), -EUCLEAN);
                ASSERT_EQ(log_device_full_errno(dev, level, 0, "test level=%d errno=0: %m", level), 0);
                ASSERT_EQ(log_device_full_errno(dev, level, SYNTHETIC_ERRNO(ENODATA), "test level=%d errno=S(ENODATA).", level), -ENODATA);
        }
}

TEST(device_in_subsystem) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

        if (sd_device_new_from_subsystem_sysname(&dev, "net", "lo") >= 0) {
                ASSERT_TRUE(device_in_subsystem(dev, "net"));
                ASSERT_FALSE(device_in_subsystem(dev, "disk"));
                ASSERT_FALSE(device_in_subsystem(dev, "subsystem"));
                ASSERT_FALSE(device_in_subsystem(dev, ""));
                ASSERT_FALSE(device_in_subsystem(dev, NULL));

                dev = sd_device_unref(dev);
        }

        ASSERT_OK(sd_device_new_from_syspath(&dev, "/sys/class/net"));
        ASSERT_FALSE(device_in_subsystem(dev, "net"));
        ASSERT_FALSE(device_in_subsystem(dev, "disk"));
        ASSERT_TRUE(device_in_subsystem(dev, "subsystem"));
        ASSERT_FALSE(device_in_subsystem(dev, ""));
        ASSERT_FALSE(device_in_subsystem(dev, NULL));

        dev = sd_device_unref(dev);

        ASSERT_OK(sd_device_new_from_syspath(&dev, "/sys/class"));
        ASSERT_FALSE(device_in_subsystem(dev, "net"));
        ASSERT_FALSE(device_in_subsystem(dev, "disk"));
        ASSERT_FALSE(device_in_subsystem(dev, "subsystem"));
        ASSERT_FALSE(device_in_subsystem(dev, ""));
        ASSERT_TRUE(device_in_subsystem(dev, NULL));
}

TEST(device_is_devtype) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;

        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_add_match_subsystem(e, "disk", true));

        FOREACH_DEVICE(e, d) {
                const char *t;

                ASSERT_OK(sd_device_get_devtype(d, &t));
                ASSERT_TRUE(device_is_devtype(d, t));
                ASSERT_FALSE(device_is_devtype(d, "hoge"));
                ASSERT_FALSE(device_is_devtype(d, ""));
                ASSERT_FALSE(device_is_devtype(d, NULL));
        }

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        ASSERT_OK(sd_device_new_from_syspath(&dev, "/sys/class/net"));
        ASSERT_FALSE(device_is_devtype(dev, "hoge"));
        ASSERT_FALSE(device_is_devtype(dev, ""));
        ASSERT_TRUE(device_is_devtype(dev, NULL));
}

static int intro(void) {
        if (path_is_mount_point("/sys") <= 0)
                return log_tests_skipped("/sys is not mounted");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
