#include "sd-hwdb.h"

#include "alloc-util.h"
#include "errno.h"
#include "tests.h"

static void test_failed_enumerate(void) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb;
        const char *key, *value;

        log_info("/* %s */", __func__);

        assert_se(sd_hwdb_new(&hwdb) == 0);

        assert_se(sd_hwdb_seek(hwdb, "no-such-modalias-should-exist") == 0);

        assert_se(sd_hwdb_enumerate(hwdb, &key, &value) == 0);
        assert_se(sd_hwdb_enumerate(hwdb, &key, NULL) == -EINVAL);
        assert_se(sd_hwdb_enumerate(hwdb, NULL, &value) == -EINVAL);
}

#define DELL_MODALIAS \
        "evdev:atkbd:dmi:bvnXXX:bvrYYY:bdZZZ:svnDellXXX:pnYYY"

static void test_basic_enumerate(void) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb;
        const char *key, *value;
        size_t len1 = 0, len2 = 0;
        int r;

        log_info("/* %s */", __func__);

        assert_se(sd_hwdb_new(&hwdb) == 0);

        assert_se(sd_hwdb_seek(hwdb, DELL_MODALIAS) == 0);

        for (;;) {
                r = sd_hwdb_enumerate(hwdb, &key, &value);
                assert(IN_SET(r, 0, 1));
                if (r == 0)
                        break;
                assert(key);
                assert(value);
                log_debug("A: \"%s\" → \"%s\"", key, value);
                len1 += strlen(key) + strlen(value);
        }

        SD_HWDB_FOREACH_PROPERTY(hwdb, DELL_MODALIAS, key, value) {
                log_debug("B: \"%s\" → \"%s\"", key, value);
                len2 += strlen(key) + strlen(value);
        }

        assert_se(len1 == len2);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_failed_enumerate();
        test_basic_enumerate();

        return 0;
}
