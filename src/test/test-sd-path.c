/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-path.h"

#include "alloc-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

static void test_sd_path_home(void) {
        log_info("/* %s */", __func__);

        for (uint64_t i = 0; i < _SD_PATH_MAX; i++) {
                _cleanup_free_ char *t, *s;

                assert_se(sd_path_home(i, NULL, &t) == 0);
                assert_se(t);
                log_info("%02"PRIu64": \"%s\"", i, t);

                assert_se(sd_path_home(i, "suffix", &s) == 0);
                assert_se(s);
                log_info("%02"PRIu64": \"%s\"", i, s);
                assert_se(endswith(s, "/suffix"));
        }

        char *tt;
        assert_se(sd_path_home(_SD_PATH_MAX, NULL, &tt) == -EOPNOTSUPP);
}

static void test_sd_path_search(void) {
        log_info("/* %s */", __func__);

        for (uint64_t i = 0; i < _SD_PATH_MAX; i++) {
                _cleanup_strv_free_ char **t, **s;
                char **item;

                assert_se(sd_path_search(i, NULL, &t) == 0);
                assert_se(t);
                log_info("%02"PRIu64":", i);
                STRV_FOREACH(item, t)
                        log_debug("  %s", *item);

                assert_se(sd_path_search(i, "suffix", &s) == 0);
                assert_se(s);
                log_info("%02"PRIu64":", i);
                STRV_FOREACH(item, s) {
                        assert_se(endswith(*item, "/suffix"));
                        log_debug("  %s", *item);
                }
        }

        char *tt;
        assert_se(sd_path_home(_SD_PATH_MAX, NULL, &tt) == -EOPNOTSUPP);
}

int main(void) {
        test_setup_logging(LOG_DEBUG);

        test_sd_path_home();
        test_sd_path_search();
}
