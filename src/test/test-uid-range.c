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
#include "virt.h"

TEST(uid_range) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL;
        uid_t search;

        assert_se(uid_range_covers(p, 0, 0));
        assert_se(!uid_range_covers(p, 0, 1));
        assert_se(!uid_range_covers(p, 100, UINT32_MAX));

        assert_se(uid_range_add_str(&p, "500-999") >= 0);
        assert_se(p);
        assert_se(p->n_entries == 1);
        assert_se(p->entries[0].start == 500);
        assert_se(p->entries[0].nr == 500);

        assert_se(!uid_range_contains(p, 499));
        assert_se(uid_range_contains(p, 500));
        assert_se(uid_range_contains(p, 999));
        assert_se(!uid_range_contains(p, 1000));

        assert_se(!uid_range_covers(p, 100, 150));
        assert_se(!uid_range_covers(p, 400, 200));
        assert_se(!uid_range_covers(p, 499, 1));
        assert_se(uid_range_covers(p, 500, 1));
        assert_se(uid_range_covers(p, 501, 10));
        assert_se(uid_range_covers(p, 999, 1));
        assert_se(!uid_range_covers(p, 999, 2));
        assert_se(!uid_range_covers(p, 1000, 1));
        assert_se(!uid_range_covers(p, 1000, 100));
        assert_se(!uid_range_covers(p, 1001, 100));

        search = UID_INVALID;
        assert_se(uid_range_next_lower(p, &search));
        assert_se(search == 999);
        assert_se(uid_range_next_lower(p, &search));
        assert_se(search == 998);
        search = 501;
        assert_se(uid_range_next_lower(p, &search));
        assert_se(search == 500);
        assert_se(uid_range_next_lower(p, &search) == -EBUSY);

        assert_se(uid_range_add_str(&p, "1000") >= 0);
        assert_se(p->n_entries == 1);
        assert_se(p->entries[0].start == 500);
        assert_se(p->entries[0].nr == 501);

        assert_se(uid_range_add_str(&p, "30-40") >= 0);
        assert_se(p->n_entries == 2);
        assert_se(p->entries[0].start == 30);
        assert_se(p->entries[0].nr == 11);
        assert_se(p->entries[1].start == 500);
        assert_se(p->entries[1].nr == 501);

        assert_se(uid_range_add_str(&p, "60-70") >= 0);
        assert_se(p->n_entries == 3);
        assert_se(p->entries[0].start == 30);
        assert_se(p->entries[0].nr == 11);
        assert_se(p->entries[1].start == 60);
        assert_se(p->entries[1].nr == 11);
        assert_se(p->entries[2].start == 500);
        assert_se(p->entries[2].nr == 501);

        assert_se(uid_range_add_str(&p, "20-2000") >= 0);
        assert_se(p->n_entries == 1);
        assert_se(p->entries[0].start == 20);
        assert_se(p->entries[0].nr == 1981);

        assert_se(uid_range_add_str(&p, "2002") >= 0);
        assert_se(p->n_entries == 2);
        assert_se(p->entries[0].start == 20);
        assert_se(p->entries[0].nr == 1981);
        assert_se(p->entries[1].start == 2002);
        assert_se(p->entries[1].nr == 1);

        assert_se(uid_range_add_str(&p, "2001") >= 0);
        assert_se(p->n_entries == 1);
        assert_se(p->entries[0].start == 20);
        assert_se(p->entries[0].nr == 1983);
}

TEST(load_userns) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL;
        _cleanup_(unlink_and_freep) char *fn = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        r = uid_range_load_userns(&p, NULL);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return;

        assert_se(r >= 0);
        assert_se(uid_range_contains(p, getuid()));

        r = running_in_userns();
        if (r == 0) {
                assert_se(p->n_entries == 1);
                assert_se(p->entries[0].start == 0);
                assert_se(p->entries[0].nr == UINT32_MAX);

                assert_se(uid_range_covers(p, 0, UINT32_MAX));
        }

        assert_se(fopen_temporary_child(NULL, &f, &fn) >= 0);
        fputs("0 0 20\n"
              "100 0 20\n", f);
        assert_se(fflush_and_check(f) >= 0);

        p = uid_range_free(p);

        assert_se(uid_range_load_userns(&p, fn) >= 0);

        assert_se(uid_range_contains(p, 0));
        assert_se(uid_range_contains(p, 19));
        assert_se(!uid_range_contains(p, 20));

        assert_se(!uid_range_contains(p, 99));
        assert_se(uid_range_contains(p, 100));
        assert_se(uid_range_contains(p, 119));
        assert_se(!uid_range_contains(p, 120));
}

TEST(uid_range_coalesce) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL;

        for (size_t i = 0; i < 10; i++) {
                assert_se(uid_range_add_internal(&p, i * 10, 10, /* coalesce = */ false) >= 0);
                assert_se(uid_range_add_internal(&p, i * 10 + 5, 10, /* coalesce = */ false) >= 0);
        }

        assert_se(uid_range_add_internal(&p, 100, 1, /* coalesce = */ true) >= 0);
        assert_se(p->n_entries == 1);
        assert_se(p->entries[0].start == 0);
        assert_se(p->entries[0].nr == 105);

        p = uid_range_free(p);

        for (size_t i = 0; i < 10; i++) {
                assert_se(uid_range_add_internal(&p, (10 - i) * 10, 10, /* coalesce = */ false) >= 0);
                assert_se(uid_range_add_internal(&p, (10 - i) * 10 + 5, 10, /* coalesce = */ false) >= 0);
        }

        assert_se(uid_range_add_internal(&p, 100, 1, /* coalesce = */ true) >= 0);
        assert_se(p->n_entries == 1);
        assert_se(p->entries[0].start == 10);
        assert_se(p->entries[0].nr == 105);

        p = uid_range_free(p);

        for (size_t i = 0; i < 10; i++) {
                assert_se(uid_range_add_internal(&p, i * 10, 10, /* coalesce = */ false) >= 0);
                assert_se(uid_range_add_internal(&p, i * 10 + 5, 10, /* coalesce = */ false) >= 0);
                assert_se(uid_range_add_internal(&p, (10 - i) * 10, 10, /* coalesce = */ false) >= 0);
                assert_se(uid_range_add_internal(&p, (10 - i) * 10 + 5, 10, /* coalesce = */ false) >= 0);
        }
        assert_se(uid_range_add_internal(&p, 100, 1, /* coalesce = */ true) >= 0);
        assert_se(p->n_entries == 1);
        assert_se(p->entries[0].start == 0);
        assert_se(p->entries[0].nr == 115);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
