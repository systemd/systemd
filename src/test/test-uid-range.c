/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>

#include "alloc-util.h"
#include "uid-range.h"
#include "user-util.h"
#include "util.h"

int main(int argc, char *argv[]) {
        _cleanup_free_ UidRange *p = NULL;
        unsigned n = 0;
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

        return 0;
}
