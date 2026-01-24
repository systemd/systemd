/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "uid-range.h"
#include "virt.h"

TEST(uid_range) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL;
        uid_t search;

        assert_se(uid_range_covers(p, 0, 0));
        assert_se(!uid_range_covers(p, 0, 1));
        assert_se(!uid_range_covers(p, 100, UINT32_MAX));
        assert_se(!uid_range_covers(p, UINT32_MAX, 1));
        assert_se(!uid_range_covers(p, UINT32_MAX - 10, 11));

        assert_se(uid_range_entries(p) == 0);
        assert_se(uid_range_size(p) == 0);
        assert_se(uid_range_is_empty(p));

        assert_se(uid_range_add_str(&p, "500-999") >= 0);
        assert_se(p);
        assert_se(uid_range_entries(p) == 1);
        assert_se(uid_range_size(p) == 500);
        assert_se(!uid_range_is_empty(p));
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
        assert_se(uid_range_entries(p) == 1);
        assert_se(p->entries[0].start == 500);
        assert_se(p->entries[0].nr == 501);

        assert_se(uid_range_add_str(&p, "30-40") >= 0);
        assert_se(uid_range_entries(p) == 2);
        assert_se(uid_range_size(p) == 500 + 1 + 11);
        assert_se(!uid_range_is_empty(p));
        assert_se(p->entries[0].start == 30);
        assert_se(p->entries[0].nr == 11);
        assert_se(p->entries[1].start == 500);
        assert_se(p->entries[1].nr == 501);

        assert_se(uid_range_add_str(&p, "60-70") >= 0);
        assert_se(uid_range_entries(p) == 3);
        assert_se(uid_range_size(p) == 500 + 1 + 11 + 11);
        assert_se(!uid_range_is_empty(p));
        assert_se(p->entries[0].start == 30);
        assert_se(p->entries[0].nr == 11);
        assert_se(p->entries[1].start == 60);
        assert_se(p->entries[1].nr == 11);
        assert_se(p->entries[2].start == 500);
        assert_se(p->entries[2].nr == 501);

        assert_se(uid_range_add_str(&p, "20-2000") >= 0);
        assert_se(uid_range_entries(p) == 1);
        assert_se(uid_range_size(p) == 1981);
        assert_se(p->entries[0].start == 20);
        assert_se(p->entries[0].nr == 1981);

        assert_se(uid_range_add_str(&p, "2002") >= 0);
        assert_se(uid_range_entries(p) == 2);
        assert_se(uid_range_size(p) == 1982);
        assert_se(p->entries[0].start == 20);
        assert_se(p->entries[0].nr == 1981);
        assert_se(p->entries[1].start == 2002);
        assert_se(p->entries[1].nr == 1);

        _cleanup_(uid_range_freep) UIDRange *q = NULL;
        assert_se(!uid_range_equal(p, q));
        assert_se(uid_range_add_str(&q, "20-2000") >= 0);
        assert_se(!uid_range_equal(p, q));
        assert_se(uid_range_add_str(&q, "2002") >= 0);
        assert_se(uid_range_equal(p, q));

        assert_se(uid_range_add_str(&p, "2001") >= 0);
        assert_se(uid_range_entries(p) == 1);
        assert_se(uid_range_size(p) == 1983);
        assert_se(p->entries[0].start == 20);
        assert_se(p->entries[0].nr == 1983);

        assert_se(uid_range_add_str(&q, "2001") >= 0);
        assert_se(uid_range_equal(p, q));
}

TEST(load_userns) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL;
        _cleanup_(unlink_and_freep) char *fn = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        r = uid_range_load_userns(NULL, UID_RANGE_USERNS_INSIDE, &p);
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

        assert_se(uid_range_load_userns(fn, UID_RANGE_USERNS_INSIDE, &p) >= 0);

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
                assert_se(uid_range_add_internal(&p, i * 10, 10, /* coalesce= */ false) >= 0);
                assert_se(uid_range_add_internal(&p, i * 10 + 5, 10, /* coalesce= */ false) >= 0);
        }

        assert_se(uid_range_add_internal(&p, 100, 1, /* coalesce= */ true) >= 0);
        assert_se(p->n_entries == 1);
        assert_se(p->entries[0].start == 0);
        assert_se(p->entries[0].nr == 105);

        p = uid_range_free(p);

        for (size_t i = 0; i < 10; i++) {
                assert_se(uid_range_add_internal(&p, (10 - i) * 10, 10, /* coalesce= */ false) >= 0);
                assert_se(uid_range_add_internal(&p, (10 - i) * 10 + 5, 10, /* coalesce= */ false) >= 0);
        }

        assert_se(uid_range_add_internal(&p, 100, 1, /* coalesce= */ true) >= 0);
        assert_se(p->n_entries == 1);
        assert_se(p->entries[0].start == 10);
        assert_se(p->entries[0].nr == 105);

        p = uid_range_free(p);

        for (size_t i = 0; i < 10; i++) {
                assert_se(uid_range_add_internal(&p, i * 10, 10, /* coalesce= */ false) >= 0);
                assert_se(uid_range_add_internal(&p, i * 10 + 5, 10, /* coalesce= */ false) >= 0);
                assert_se(uid_range_add_internal(&p, (10 - i) * 10, 10, /* coalesce= */ false) >= 0);
                assert_se(uid_range_add_internal(&p, (10 - i) * 10 + 5, 10, /* coalesce= */ false) >= 0);
        }
        assert_se(uid_range_add_internal(&p, 100, 1, /* coalesce= */ true) >= 0);
        assert_se(p->n_entries == 1);
        assert_se(p->entries[0].start == 0);
        assert_se(p->entries[0].nr == 115);
}

TEST(uid_range_intersect) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL;

        /* Build a range: 100-199, 300-399, 500-599 */
        assert_se(uid_range_add_str(&p, "100-199") >= 0);
        assert_se(uid_range_add_str(&p, "300-399") >= 0);
        assert_se(uid_range_add_str(&p, "500-599") >= 0);
        assert_se(uid_range_entries(p) == 3);

        /* Intersect with range that covers all entries */
        assert_se(uid_range_intersect(p, 0, 1000) >= 0);
        assert_se(uid_range_entries(p) == 3);
        assert_se(p->entries[0].start == 100);
        assert_se(p->entries[0].nr == 100);
        assert_se(p->entries[1].start == 300);
        assert_se(p->entries[1].nr == 100);
        assert_se(p->entries[2].start == 500);
        assert_se(p->entries[2].nr == 100);

        /* Intersect with range that excludes first and last entries */
        assert_se(uid_range_intersect(p, 200, 499) >= 0);
        assert_se(uid_range_entries(p) == 1);
        assert_se(p->entries[0].start == 300);
        assert_se(p->entries[0].nr == 100);

        p = uid_range_free(p);

        /* Test partial overlap - trimming from both sides */
        assert_se(uid_range_add_str(&p, "100-199") >= 0);
        assert_se(uid_range_intersect(p, 150, 180) >= 0);
        assert_se(uid_range_entries(p) == 1);
        assert_se(p->entries[0].start == 150);
        assert_se(p->entries[0].nr == 31);

        p = uid_range_free(p);

        /* Test intersection that removes all entries */
        assert_se(uid_range_add_str(&p, "100-199") >= 0);
        assert_se(uid_range_intersect(p, 500, 600) >= 0);
        assert_se(uid_range_is_empty(p));

        p = uid_range_free(p);

        /* Test invalid min > max */
        assert_se(uid_range_add_str(&p, "100-199") >= 0);
        assert_se(uid_range_intersect(p, 200, 100) == -EINVAL);
}

TEST(uid_range_partition) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL;

        /* Single entry that divides evenly */
        assert_se(uid_range_add_str(&p, "0-299") >= 0);
        assert_se(uid_range_entries(p) == 1);
        assert_se(uid_range_partition(p, 100) >= 0);
        assert_se(uid_range_entries(p) == 3);
        assert_se(p->entries[0].start == 0);
        assert_se(p->entries[0].nr == 100);
        assert_se(p->entries[1].start == 100);
        assert_se(p->entries[1].nr == 100);
        assert_se(p->entries[2].start == 200);
        assert_se(p->entries[2].nr == 100);

        p = uid_range_free(p);

        /* Entry with remainder (gets truncated) */
        assert_se(uid_range_add_str(&p, "0-249") >= 0);
        assert_se(uid_range_partition(p, 100) >= 0);
        assert_se(uid_range_entries(p) == 2);
        assert_se(p->entries[0].start == 0);
        assert_se(p->entries[0].nr == 100);
        assert_se(p->entries[1].start == 100);
        assert_se(p->entries[1].nr == 100);

        p = uid_range_free(p);

        /* Entry smaller than partition size - gets dropped */
        assert_se(uid_range_add_str(&p, "0-49") >= 0);
        assert_se(uid_range_partition(p, 100) >= 0);
        assert_se(uid_range_is_empty(p));

        p = uid_range_free(p);

        /* Multiple entries */
        assert_se(uid_range_add_str(&p, "0-199") >= 0);
        assert_se(uid_range_add_str(&p, "1000-1299") >= 0);
        assert_se(uid_range_entries(p) == 2);
        assert_se(uid_range_partition(p, 100) >= 0);
        assert_se(uid_range_entries(p) == 5);
        assert_se(p->entries[0].start == 0);
        assert_se(p->entries[0].nr == 100);
        assert_se(p->entries[1].start == 100);
        assert_se(p->entries[1].nr == 100);
        assert_se(p->entries[2].start == 1000);
        assert_se(p->entries[2].nr == 100);
        assert_se(p->entries[3].start == 1100);
        assert_se(p->entries[3].nr == 100);
        assert_se(p->entries[4].start == 1200);
        assert_se(p->entries[4].nr == 100);

        p = uid_range_free(p);

        /* Partition size of 1 */
        assert_se(uid_range_add_str(&p, "100-102") >= 0);
        assert_se(uid_range_partition(p, 1) >= 0);
        assert_se(uid_range_entries(p) == 3);
        assert_se(p->entries[0].start == 100);
        assert_se(p->entries[0].nr == 1);
        assert_se(p->entries[1].start == 101);
        assert_se(p->entries[1].nr == 1);
        assert_se(p->entries[2].start == 102);
        assert_se(p->entries[2].nr == 1);
}

TEST(uid_range_copy) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL, *copy = NULL;

        /* Copy NULL range */
        assert_se(uid_range_copy(NULL, &copy) >= 0);
        assert_se(uid_range_is_empty(copy));

        copy = uid_range_free(copy);

        /* Copy empty range */
        p = new0(UIDRange, 1);
        assert_se(p);
        assert_se(uid_range_copy(p, &copy) >= 0);
        assert_se(copy);
        assert_se(uid_range_is_empty(copy));

        p = uid_range_free(p);
        copy = uid_range_free(copy);

        /* Copy range with entries */
        assert_se(uid_range_add_str(&p, "100-199") >= 0);
        assert_se(uid_range_add_str(&p, "300-399") >= 0);
        assert_se(uid_range_copy(p, &copy) >= 0);
        assert_se(uid_range_equal(p, copy));

        /* Verify it's a deep copy - modifying original doesn't affect copy */
        assert_se(uid_range_add_str(&p, "500-599") >= 0);
        assert_se(!uid_range_equal(p, copy));
        assert_se(uid_range_entries(copy) == 2);
}

TEST(uid_range_remove) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL;

        /* Build a range: 100-199 */
        assert_se(uid_range_add_str(&p, "100-199") >= 0);

        /* Remove with size 0 - no-op */
        assert_se(uid_range_remove(p, 150, 0) >= 0);
        assert_se(uid_range_entries(p) == 1);
        assert_se(p->entries[0].start == 100);
        assert_se(p->entries[0].nr == 100);

        /* Remove range that doesn't overlap - no change */
        assert_se(uid_range_remove(p, 0, 50) >= 0);
        assert_se(uid_range_entries(p) == 1);
        assert_se(p->entries[0].start == 100);
        assert_se(p->entries[0].nr == 100);

        assert_se(uid_range_remove(p, 300, 50) >= 0);
        assert_se(uid_range_entries(p) == 1);
        assert_se(p->entries[0].start == 100);
        assert_se(p->entries[0].nr == 100);

        /* Remove from the start of the entry */
        assert_se(uid_range_remove(p, 100, 10) >= 0);
        assert_se(uid_range_entries(p) == 1);
        assert_se(p->entries[0].start == 110);
        assert_se(p->entries[0].nr == 90);

        /* Remove from the end of the entry */
        assert_se(uid_range_remove(p, 190, 10) >= 0);
        assert_se(uid_range_entries(p) == 1);
        assert_se(p->entries[0].start == 110);
        assert_se(p->entries[0].nr == 80);

        /* Remove from the middle - splits the entry */
        assert_se(uid_range_remove(p, 140, 20) >= 0);
        assert_se(uid_range_entries(p) == 2);
        assert_se(p->entries[0].start == 110);
        assert_se(p->entries[0].nr == 30);
        assert_se(p->entries[1].start == 160);
        assert_se(p->entries[1].nr == 30);

        p = uid_range_free(p);

        /* Remove entire entry */
        assert_se(uid_range_add_str(&p, "100-199") >= 0);
        assert_se(uid_range_remove(p, 100, 100) >= 0);
        assert_se(uid_range_is_empty(p));

        p = uid_range_free(p);

        /* Remove range larger than entry */
        assert_se(uid_range_add_str(&p, "100-199") >= 0);
        assert_se(uid_range_remove(p, 50, 200) >= 0);
        assert_se(uid_range_is_empty(p));

        p = uid_range_free(p);

        /* Remove affecting multiple entries */
        assert_se(uid_range_add_str(&p, "100-199") >= 0);
        assert_se(uid_range_add_str(&p, "300-399") >= 0);
        assert_se(uid_range_add_str(&p, "500-599") >= 0);
        assert_se(uid_range_entries(p) == 3);

        /* Remove range spanning the middle entry completely and trimming others */
        assert_se(uid_range_remove(p, 150, 400) >= 0);
        assert_se(uid_range_entries(p) == 2);
        assert_se(p->entries[0].start == 100);
        assert_se(p->entries[0].nr == 50);
        assert_se(p->entries[1].start == 550);
        assert_se(p->entries[1].nr == 50);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
