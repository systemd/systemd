/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"

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

TEST(device_in_subsystem_devtype_sysname_startswith) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;

        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_allow_uninitialized(e));
        ASSERT_OK(sd_device_enumerator_add_match_subsystem(e, "block", /* match= */ true));

        FOREACH_DEVICE(e, d) {
                ASSERT_OK_ZERO(device_in_subsystem(d, "net"));
                ASSERT_OK_POSITIVE(device_in_subsystem(d, "block"));
                ASSERT_OK_ZERO(device_in_subsystem(d, "subsystem"));
                ASSERT_OK_ZERO(device_in_subsystem(d, "", "net"));
                ASSERT_OK_POSITIVE(device_in_subsystem(d, "net", "block"));
                ASSERT_OK_POSITIVE(device_in_subsystem(d, "block", "subsystem"));
                ASSERT_OK_POSITIVE(device_in_subsystem(d, "block", ""));
                ASSERT_OK_ZERO(device_in_subsystem(d, ""));
                ASSERT_OK_ZERO(device_in_subsystem(d, NULL));

                ASSERT_OK_ZERO(device_in_subsystem_strv(d, STRV_MAKE("net")));
                ASSERT_OK_ZERO(device_in_subsystem_strv(d, STRV_MAKE("", "net")));
                ASSERT_OK_POSITIVE(device_in_subsystem_strv(d, STRV_MAKE("net", "block")));
                ASSERT_OK_POSITIVE(device_in_subsystem_strv(d, STRV_MAKE("block", "subsystem")));
                ASSERT_OK_POSITIVE(device_in_subsystem_strv(d, STRV_MAKE("block", "")));
                ASSERT_OK_ZERO(device_in_subsystem_strv(d, STRV_MAKE("")));
                ASSERT_OK_ZERO(device_in_subsystem_strv(d, STRV_MAKE(NULL)));
                ASSERT_OK_ZERO(device_in_subsystem_strv(d, /* subsystems= */ NULL));

                const char *t;
                ASSERT_OK(sd_device_get_devtype(d, &t));
                ASSERT_OK_POSITIVE(device_is_devtype(d, t));
                ASSERT_OK_ZERO(device_is_devtype(d, "hoge"));
                ASSERT_OK_ZERO(device_is_devtype(d, ""));
                ASSERT_OK_ZERO(device_is_devtype(d, /* devtype= */ NULL));

                ASSERT_OK_POSITIVE(device_is_subsystem_devtype(d, "block", t));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(d, "block", "hoge"));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(d, "block", ""));
                ASSERT_OK_POSITIVE(device_is_subsystem_devtype(d, "block", /* devtype= */ NULL));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(d, "net", t));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(d, "net", "hoge"));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(d, "net", ""));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(d, "net", /* devtype= */ NULL));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(d, "subsystem", t));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(d, "subsystem", "hoge"));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(d, "subsystem", ""));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(d, "subsystem", /* devtype= */ NULL));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(d, /* subsystem= */ NULL, t));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(d, /* subsystem= */ NULL, "hoge"));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(d, /* subsystem= */ NULL, ""));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(d, /* subsystem= */ NULL, /* devtype= */ NULL));

                const char *s;
                ASSERT_OK(sd_device_get_sysname(d, &s));
                ASSERT_OK_POSITIVE(device_sysname_startswith(d, s));
                ASSERT_OK_POSITIVE(device_sysname_startswith(d, CHAR_TO_STR(s[0])));
                ASSERT_OK_POSITIVE(device_sysname_startswith(d, ""));
                ASSERT_OK_ZERO(device_sysname_startswith(d, "00"));
        }

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

        if (sd_device_new_from_subsystem_sysname(&dev, "net", "lo") >= 0) {
                ASSERT_OK_POSITIVE(device_in_subsystem(dev, "net"));
                ASSERT_OK_ZERO(device_in_subsystem(dev, "block"));
                ASSERT_OK_ZERO(device_in_subsystem(dev, "subsystem"));
                ASSERT_OK_POSITIVE(device_in_subsystem(dev, "", "net"));
                ASSERT_OK_POSITIVE(device_in_subsystem(dev, "net", "block"));
                ASSERT_OK_ZERO(device_in_subsystem(dev, "block", "subsystem"));
                ASSERT_OK_ZERO(device_in_subsystem(dev, "block", ""));
                ASSERT_OK_ZERO(device_in_subsystem(dev, ""));
                ASSERT_OK_ZERO(device_in_subsystem(dev, NULL));

                ASSERT_OK_POSITIVE(device_in_subsystem_strv(dev, STRV_MAKE("net")));
                ASSERT_OK_POSITIVE(device_in_subsystem_strv(dev, STRV_MAKE("", "net")));
                ASSERT_OK_POSITIVE(device_in_subsystem_strv(dev, STRV_MAKE("net", "block")));
                ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE("block", "subsystem")));
                ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE("block", "")));
                ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE("")));
                ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE(NULL)));
                ASSERT_OK_ZERO(device_in_subsystem_strv(dev, /* subsystems= */ NULL));

                ASSERT_OK_ZERO(device_is_devtype(dev, "hoge"));
                ASSERT_OK_ZERO(device_is_devtype(dev, ""));
                ASSERT_OK_POSITIVE(device_is_devtype(dev, /* devtype= */ NULL));

                ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "block", "hoge"));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "block", ""));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "block", /* devtype= */ NULL));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "net", "hoge"));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "net", ""));
                ASSERT_OK_POSITIVE(device_is_subsystem_devtype(dev, "net", /* devtype= */ NULL));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "subsystem", "hoge"));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "subsystem", ""));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "subsystem", /* devtype= */ NULL));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, /* subsystem= */ NULL, "hoge"));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, /* subsystem= */ NULL, ""));
                ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, /* subsystem= */ NULL, /* devtype= */ NULL));

                ASSERT_OK_POSITIVE(device_sysname_startswith(dev, "lo"));
                ASSERT_OK_POSITIVE(device_sysname_startswith(dev, "l"));
                ASSERT_OK_POSITIVE(device_sysname_startswith(dev, ""));
                ASSERT_OK_ZERO(device_sysname_startswith(dev, "00"));

                dev = sd_device_unref(dev);
        }

        ASSERT_OK(sd_device_new_from_syspath(&dev, "/sys/class/net"));
        ASSERT_OK_ZERO(device_in_subsystem(dev, "net"));
        ASSERT_OK_ZERO(device_in_subsystem(dev, "block"));
        ASSERT_OK_POSITIVE(device_in_subsystem(dev, "subsystem"));
        ASSERT_OK_ZERO(device_in_subsystem(dev, "", "net"));
        ASSERT_OK_ZERO(device_in_subsystem(dev, "net", "block"));
        ASSERT_OK_POSITIVE(device_in_subsystem(dev, "block", "subsystem"));
        ASSERT_OK_ZERO(device_in_subsystem(dev, "block", ""));
        ASSERT_OK_ZERO(device_in_subsystem(dev, ""));
        ASSERT_OK_ZERO(device_in_subsystem(dev, NULL));

        ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE("net")));
        ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE("", "net")));
        ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE("net", "block")));
        ASSERT_OK_POSITIVE(device_in_subsystem_strv(dev, STRV_MAKE("block", "subsystem")));
        ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE("block", "")));
        ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE("")));
        ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE(NULL)));
        ASSERT_OK_ZERO(device_in_subsystem_strv(dev, /* subsystems= */ NULL));

        ASSERT_OK_ZERO(device_is_devtype(dev, "hoge"));
        ASSERT_OK_ZERO(device_is_devtype(dev, ""));
        ASSERT_OK_POSITIVE(device_is_devtype(dev, /* devtype= */ NULL));

        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "block", "hoge"));
        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "block", ""));
        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "block", /* devtype= */ NULL));
        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "subsystem", "hoge"));
        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "subsystem", ""));
        ASSERT_OK_POSITIVE(device_is_subsystem_devtype(dev, "subsystem", /* devtype= */ NULL));
        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, /* subsystem= */ NULL, "hoge"));
        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, /* subsystem= */ NULL, ""));
        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, /* subsystem= */ NULL, /* devtype= */ NULL));

        ASSERT_OK_POSITIVE(device_sysname_startswith(dev, "net"));
        ASSERT_OK_POSITIVE(device_sysname_startswith(dev, "n"));
        ASSERT_OK_POSITIVE(device_sysname_startswith(dev, ""));
        ASSERT_OK_ZERO(device_sysname_startswith(dev, "00"));

        dev = sd_device_unref(dev);

        ASSERT_OK(sd_device_new_from_syspath(&dev, "/sys/class"));
        ASSERT_OK_ZERO(device_in_subsystem(dev, "net"));
        ASSERT_OK_ZERO(device_in_subsystem(dev, "block"));
        ASSERT_OK_ZERO(device_in_subsystem(dev, "subsystem"));
        ASSERT_OK_ZERO(device_in_subsystem(dev, "", "net"));
        ASSERT_OK_ZERO(device_in_subsystem(dev, "net", "block"));
        ASSERT_OK_ZERO(device_in_subsystem(dev, "block", "subsystem"));
        ASSERT_OK_ZERO(device_in_subsystem(dev, "block", ""));
        ASSERT_OK_ZERO(device_in_subsystem(dev, ""));
        ASSERT_OK_POSITIVE(device_in_subsystem(dev, NULL));

        ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE("net")));
        ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE("", "net")));
        ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE("net", "block")));
        ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE("block", "subsystem")));
        ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE("block", "")));
        ASSERT_OK_ZERO(device_in_subsystem_strv(dev, STRV_MAKE("")));
        ASSERT_OK_POSITIVE(device_in_subsystem_strv(dev, STRV_MAKE(NULL)));
        ASSERT_OK_POSITIVE(device_in_subsystem_strv(dev, /* subsystems= */ NULL));

        ASSERT_OK_ZERO(device_is_devtype(dev, "hoge"));
        ASSERT_OK_ZERO(device_is_devtype(dev, ""));
        ASSERT_OK_POSITIVE(device_is_devtype(dev, /* devtype= */ NULL));

        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "block", "hoge"));
        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "block", ""));
        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "block", /* devtype= */ NULL));
        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "subsystem", "hoge"));
        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "subsystem", ""));
        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, "subsystem", /* devtype= */ NULL));
        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, /* subsystem= */ NULL, "hoge"));
        ASSERT_OK_ZERO(device_is_subsystem_devtype(dev, /* subsystem= */ NULL, ""));
        ASSERT_OK_POSITIVE(device_is_subsystem_devtype(dev, /* subsystem= */ NULL, /* devtype= */ NULL));

        ASSERT_OK_POSITIVE(device_sysname_startswith(dev, "class"));
        ASSERT_OK_POSITIVE(device_sysname_startswith(dev, "c"));
        ASSERT_OK_POSITIVE(device_sysname_startswith(dev, ""));
        ASSERT_OK_ZERO(device_sysname_startswith(dev, "00"));
}

static int intro(void) {
        if (path_is_mount_point("/sys") <= 0)
                return log_tests_skipped("/sys is not mounted");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
