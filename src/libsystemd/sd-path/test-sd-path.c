/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-path.h"

#include "alloc-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(sd_path_lookup) {
        for (uint64_t i = 0; i < _SD_PATH_MAX; i++) {
                _cleanup_free_ char *t = NULL, *s = NULL;
                int r;

                r = sd_path_lookup(i, /* suffix= */ NULL, &t);
                if (i == SD_PATH_USER_RUNTIME && r == -ENXIO)
                        continue;
                ASSERT_OK_ZERO(r);
                ASSERT_NOT_NULL(t);
                log_info("%02"PRIu64": \"%s\"", i, t);

                ASSERT_OK_ZERO(sd_path_lookup(i, "suffix", &s));
                ASSERT_NOT_NULL(s);
                log_info("%02"PRIu64": \"%s\"", i, s);
                ASSERT_NOT_NULL(endswith(s, "/suffix"));
        }

        char *tt;
        ASSERT_ERROR(sd_path_lookup(_SD_PATH_MAX, /* suffix= */ NULL, &tt), EOPNOTSUPP);
}

TEST(sd_path_lookup_strv) {
        for (uint64_t i = 0; i < _SD_PATH_MAX; i++) {
                _cleanup_strv_free_ char **t = NULL, **s = NULL;
                int r;

                r = sd_path_lookup_strv(i, /* suffix= */ NULL, &t);
                if (i == SD_PATH_USER_RUNTIME && r == -ENXIO)
                        continue;
                ASSERT_OK_ZERO(r);
                ASSERT_NOT_NULL(t);
                log_info("%02"PRIu64":", i);
                STRV_FOREACH(item, t)
                        log_debug("  %s", *item);

                ASSERT_OK_ZERO(sd_path_lookup_strv(i, "suffix", &s));
                ASSERT_NOT_NULL(s);
                log_info("%02"PRIu64":", i);
                STRV_FOREACH(item, s) {
                        ASSERT_NOT_NULL(endswith(*item, "/suffix"));
                        log_debug("  %s", *item);
                }
        }

        char *tt;
        ASSERT_ERROR(sd_path_lookup(_SD_PATH_MAX, /* suffix= */ NULL, &tt), EOPNOTSUPP);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
