/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "uid-range.h"
#include "user-util.h"
#include "util.h"
#include "virt.h"

TEST(uid_range) {
        _cleanup_free_ UidRange *p = NULL;
        size_t n = 0;
        uid_t search;

        assert_se(uid_range_add_str(&p, &n, "500-999") >= 0);
        assert_se(n == 1);
        assert_se(p[0].start == 500);
        assert_se(p[0].nr == 500);

        assert_se(!uid_range_contains(p, n, 499));
        assert_se(uid_range_contains(p, n, 500));
        assert_se(uid_range_contains(p, n, 999));
        assert_se(!uid_range_contains(p, n, 1000));

        search = UID_INVALID;
        assert_se(uid_range_next_lower(p, n, &search));
        assert_se(search == 999);
        assert_se(uid_range_next_lower(p, n, &search));
        assert_se(search == 998);
        search = 501;
        assert_se(uid_range_next_lower(p, n, &search));
        assert_se(search == 500);
        assert_se(uid_range_next_lower(p, n, &search) == -EBUSY);

        assert_se(uid_range_add_str(&p, &n, "1000") >= 0);
        assert_se(n == 1);
        assert_se(p[0].start == 500);
        assert_se(p[0].nr == 501);

        assert_se(uid_range_add_str(&p, &n, "30-40") >= 0);
        assert_se(n == 2);
        assert_se(p[0].start == 30);
        assert_se(p[0].nr == 11);
        assert_se(p[1].start == 500);
        assert_se(p[1].nr == 501);

        assert_se(uid_range_add_str(&p, &n, "60-70") >= 0);
        assert_se(n == 3);
        assert_se(p[0].start == 30);
        assert_se(p[0].nr == 11);
        assert_se(p[1].start == 60);
        assert_se(p[1].nr == 11);
        assert_se(p[2].start == 500);
        assert_se(p[2].nr == 501);

        assert_se(uid_range_add_str(&p, &n, "20-2000") >= 0);
        assert_se(n == 1);
        assert_se(p[0].start == 20);
        assert_se(p[0].nr == 1981);

        assert_se(uid_range_add_str(&p, &n, "2002") >= 0);
        assert_se(n == 2);
        assert_se(p[0].start == 20);
        assert_se(p[0].nr == 1981);
        assert_se(p[1].start == 2002);
        assert_se(p[1].nr == 1);

        assert_se(uid_range_add_str(&p, &n, "2001") >= 0);
        assert_se(n == 1);
        assert_se(p[0].start == 20);
        assert_se(p[0].nr == 1983);
}

TEST(load_userns) {
        _cleanup_(unlink_and_freep) char *fn = NULL;
        _cleanup_free_ UidRange *p = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        size_t n = 0;
        int r;

        r = uid_range_load_userns(&p, &n, NULL);
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return;

        assert_se(r >= 0);
        assert_se(uid_range_contains(p, n, getuid()));

        r = running_in_userns();
        if (r == 0) {
                assert_se(n == 1);
                assert_se(p[0].start == 0);
                assert_se(p[0].nr == UINT32_MAX);
        }

        assert_se(fopen_temporary(NULL, &f, &fn) >= 0);
        fputs("0 0 20\n"
              "100 0 20\n", f);
        assert_se(fflush_and_check(f) >= 0);

        p = mfree(p);
        n = 0;

        assert_se(uid_range_load_userns(&p, &n, fn) >= 0);

        assert_se(uid_range_contains(p, n, 0));
        assert_se(uid_range_contains(p, n, 19));
        assert_se(!uid_range_contains(p, n, 20));

        assert_se(!uid_range_contains(p, n, 99));
        assert_se(uid_range_contains(p, n, 100));
        assert_se(uid_range_contains(p, n, 119));
        assert_se(!uid_range_contains(p, n, 120));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
