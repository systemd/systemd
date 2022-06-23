/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-hwdb.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "errno.h"
#include "hwdb-internal.h"
#include "nulstr-util.h"
#include "tests.h"

TEST(failed_enumerate) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        const char *key, *value;

        assert_se(sd_hwdb_new(&hwdb) == 0);

        assert_se(sd_hwdb_seek(hwdb, "no-such-modalias-should-exist") == 0);

        assert_se(sd_hwdb_enumerate(hwdb, &key, &value) == 0);
        assert_se(sd_hwdb_enumerate(hwdb, &key, NULL) == -EINVAL);
        assert_se(sd_hwdb_enumerate(hwdb, NULL, &value) == -EINVAL);
}

#define DELL_MODALIAS \
        "evdev:atkbd:dmi:bvnXXX:bvrYYY:bdZZZ:svnDellXXX:pnYYY:"

TEST(basic_enumerate) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        const char *key, *value;
        size_t len1 = 0, len2 = 0;
        int r;

        assert_se(sd_hwdb_new(&hwdb) == 0);

        assert_se(sd_hwdb_seek(hwdb, DELL_MODALIAS) == 0);

        for (;;) {
                r = sd_hwdb_enumerate(hwdb, &key, &value);
                assert_se(IN_SET(r, 0, 1));
                if (r == 0)
                        break;
                assert_se(key);
                assert_se(value);
                log_debug("A: \"%s\" → \"%s\"", key, value);
                len1 += strlen(key) + strlen(value);
        }

        SD_HWDB_FOREACH_PROPERTY(hwdb, DELL_MODALIAS, key, value) {
                log_debug("B: \"%s\" → \"%s\"", key, value);
                len2 += strlen(key) + strlen(value);
        }

        assert_se(len1 == len2);
}

TEST(sd_hwdb_new_from_path) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        const char *hwdb_bin_path = NULL;
        int r;

        assert_se(sd_hwdb_new_from_path(NULL, &hwdb) == -EINVAL);
        assert_se(sd_hwdb_new_from_path("", &hwdb) == -EINVAL);
        assert_se(sd_hwdb_new_from_path("/path/that/should/not/exist", &hwdb) < 0);

        NULSTR_FOREACH(hwdb_bin_path, hwdb_bin_paths) {
                r = sd_hwdb_new_from_path(hwdb_bin_path, &hwdb);
                if (r >= 0)
                        break;
        }

        assert_se(r >= 0);
}

static int intro(void) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        int r;

        r = sd_hwdb_new(&hwdb);
        if (r == -ENOENT || ERRNO_IS_PRIVILEGE(r))
                return log_tests_skipped_errno(r, "cannot open hwdb");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
