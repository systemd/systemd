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

        ASSERT_TRUE(uid_range_covers(p, 0, 0));
        ASSERT_FALSE(uid_range_covers(p, 0, 1));
        ASSERT_FALSE(uid_range_covers(p, 100, UINT32_MAX));
        ASSERT_FALSE(uid_range_covers(p, UINT32_MAX, 1));
        ASSERT_FALSE(uid_range_covers(p, UINT32_MAX - 10, 11));

        ASSERT_EQ(uid_range_entries(p), 0U);
        ASSERT_EQ(uid_range_size(p), 0U);
        ASSERT_TRUE(uid_range_is_empty(p));

        ASSERT_OK(uid_range_add_str(&p, "500-999"));
        ASSERT_NOT_NULL(p);
        ASSERT_EQ(uid_range_entries(p), 1U);
        ASSERT_EQ(uid_range_size(p), 500U);
        ASSERT_FALSE(uid_range_is_empty(p));
        ASSERT_EQ(p->entries[0].start, 500U);
        ASSERT_EQ(p->entries[0].nr, 500U);

        ASSERT_FALSE(uid_range_contains(p, 499));
        ASSERT_TRUE(uid_range_contains(p, 500));
        ASSERT_TRUE(uid_range_contains(p, 999));
        ASSERT_FALSE(uid_range_contains(p, 1000));

        ASSERT_FALSE(uid_range_covers(p, 100, 150));
        ASSERT_FALSE(uid_range_covers(p, 400, 200));
        ASSERT_FALSE(uid_range_covers(p, 499, 1));
        ASSERT_TRUE(uid_range_covers(p, 500, 1));
        ASSERT_TRUE(uid_range_covers(p, 501, 10));
        ASSERT_TRUE(uid_range_covers(p, 999, 1));
        ASSERT_FALSE(uid_range_covers(p, 999, 2));
        ASSERT_FALSE(uid_range_covers(p, 1000, 1));
        ASSERT_FALSE(uid_range_covers(p, 1000, 100));
        ASSERT_FALSE(uid_range_covers(p, 1001, 100));

        search = UID_INVALID;
        ASSERT_OK_POSITIVE(uid_range_next_lower(p, &search));
        ASSERT_EQ(search, 999U);
        ASSERT_OK_POSITIVE(uid_range_next_lower(p, &search));
        ASSERT_EQ(search, 998U);
        search = 501;
        ASSERT_OK_POSITIVE(uid_range_next_lower(p, &search));
        ASSERT_EQ(search, 500U);
        ASSERT_ERROR(uid_range_next_lower(p, &search), EBUSY);

        ASSERT_OK(uid_range_add_str(&p, "1000"));
        ASSERT_EQ(uid_range_entries(p), 1U);
        ASSERT_EQ(p->entries[0].start, 500U);
        ASSERT_EQ(p->entries[0].nr, 501U);

        ASSERT_OK(uid_range_add_str(&p, "30-40"));
        ASSERT_EQ(uid_range_entries(p), 2U);
        ASSERT_EQ(uid_range_size(p), 500U + 1U + 11U);
        ASSERT_FALSE(uid_range_is_empty(p));
        ASSERT_EQ(p->entries[0].start,  30U);
        ASSERT_EQ(p->entries[0].nr,  11U);
        ASSERT_EQ(p->entries[1].start , 500U);
        ASSERT_EQ(p->entries[1].nr , 501U);

        ASSERT_OK(uid_range_add_str(&p, "60-70"));
        ASSERT_EQ(uid_range_entries(p), 3U);
        ASSERT_EQ(uid_range_size(p), 500U + 1U + 11U + 11U);
        ASSERT_FALSE(uid_range_is_empty(p));
        ASSERT_EQ(p->entries[0].start, 30U);
        ASSERT_EQ(p->entries[0].nr, 11U);
        ASSERT_EQ(p->entries[1].start, 60U);
        ASSERT_EQ(p->entries[1].nr, 11U);
        ASSERT_EQ(p->entries[2].start, 500U);
        ASSERT_EQ(p->entries[2].nr, 501U);

        ASSERT_OK(uid_range_add_str(&p, "20-2000"));
        ASSERT_EQ(uid_range_entries(p), 1U);
        ASSERT_EQ(uid_range_size(p), 1981U);
        ASSERT_EQ(p->entries[0].start, 20U);
        ASSERT_EQ(p->entries[0].nr, 1981U);

        ASSERT_OK(uid_range_add_str(&p, "2002"));
        ASSERT_EQ(uid_range_entries(p), 2U);
        ASSERT_EQ(uid_range_size(p), 1982U);
        ASSERT_EQ(p->entries[0].start, 20U);
        ASSERT_EQ(p->entries[0].nr, 1981U);
        ASSERT_EQ(p->entries[1].start, 2002U);
        ASSERT_EQ(p->entries[1].nr, 1U);

        _cleanup_(uid_range_freep) UIDRange *q = NULL;
        ASSERT_FALSE(uid_range_equal(p, q));
        ASSERT_OK(uid_range_add_str(&q, "20-2000"));
        ASSERT_FALSE(uid_range_equal(p, q));
        ASSERT_OK(uid_range_add_str(&q, "2002"));
        ASSERT_TRUE(uid_range_equal(p, q));

        ASSERT_OK(uid_range_add_str(&p, "2001"));
        ASSERT_EQ(uid_range_entries(p), 1U);
        ASSERT_EQ(uid_range_size(p), 1983U);
        ASSERT_EQ(p->entries[0].start, 20U);
        ASSERT_EQ(p->entries[0].nr, 1983U);

        ASSERT_OK(uid_range_add_str(&q, "2001"));
        ASSERT_TRUE(uid_range_equal(p, q));
}

TEST(load_userns) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL;
        _cleanup_(unlink_and_freep) char *fn = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        r = uid_range_load_userns(NULL, UID_RANGE_USERNS_INSIDE, &p);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return;

        ASSERT_OK(r);
        ASSERT_TRUE(uid_range_contains(p, getuid()));

        r = running_in_userns();
        if (r == 0) {
                ASSERT_EQ(p->n_entries, 1U);
                ASSERT_EQ(p->entries[0].start, 0U);
                ASSERT_EQ(p->entries[0].nr, UINT32_MAX);

                ASSERT_TRUE(uid_range_covers(p, 0, UINT32_MAX));
        }

        ASSERT_OK(fopen_temporary_child(NULL, &f, &fn));
        fputs("0 0 20\n"
              "100 0 20\n", f);
        ASSERT_OK(fflush_and_check(f));

        p = uid_range_free(p);

        ASSERT_OK(uid_range_load_userns(fn, UID_RANGE_USERNS_INSIDE, &p));

        ASSERT_TRUE(uid_range_contains(p, 0));
        ASSERT_TRUE(uid_range_contains(p, 19));
        ASSERT_FALSE(uid_range_contains(p, 20));

        ASSERT_FALSE(uid_range_contains(p, 99));
        ASSERT_TRUE(uid_range_contains(p, 100));
        ASSERT_TRUE(uid_range_contains(p, 119));
        ASSERT_FALSE(uid_range_contains(p, 120));
}

TEST(uid_range_coalesce) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL;

        for (size_t i = 0; i < 10; i++) {
                ASSERT_OK(uid_range_add_internal(&p, i * 10, 10, /* coalesce= */ false));
                ASSERT_OK(uid_range_add_internal(&p, i * 10 + 5, 10, /* coalesce= */ false));
        }

        ASSERT_OK(uid_range_add_internal(&p, 100, 1, /* coalesce= */ true));
        ASSERT_EQ(p->n_entries, 1U);
        ASSERT_EQ(p->entries[0].start, 0U);
        ASSERT_EQ(p->entries[0].nr, 105U);

        p = uid_range_free(p);

        for (size_t i = 0; i < 10; i++) {
                ASSERT_OK(uid_range_add_internal(&p, (10 - i) * 10, 10, /* coalesce= */ false));
                ASSERT_OK(uid_range_add_internal(&p, (10 - i) * 10 + 5, 10, /* coalesce= */ false));
        }

        ASSERT_OK(uid_range_add_internal(&p, 100, 1, /* coalesce= */ true));
        ASSERT_EQ(p->n_entries, 1U);
        ASSERT_EQ(p->entries[0].start, 10U);
        ASSERT_EQ(p->entries[0].nr, 105U);

        p = uid_range_free(p);

        for (size_t i = 0; i < 10; i++) {
                ASSERT_OK(uid_range_add_internal(&p, i * 10, 10, /* coalesce= */ false));
                ASSERT_OK(uid_range_add_internal(&p, i * 10 + 5, 10, /* coalesce= */ false));
                ASSERT_OK(uid_range_add_internal(&p, (10 - i) * 10, 10, /* coalesce= */ false));
                ASSERT_OK(uid_range_add_internal(&p, (10 - i) * 10 + 5, 10, /* coalesce= */ false));
        }
        ASSERT_OK(uid_range_add_internal(&p, 100, 1, /* coalesce= */ true));
        ASSERT_EQ(p->n_entries, 1U);
        ASSERT_EQ(p->entries[0].start, 0U);
        ASSERT_EQ(p->entries[0].nr, 115U);
}

TEST(uid_range_clip) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL;

        /* Build a range: 100-199, 300-399, 500-599 */
        ASSERT_OK(uid_range_add_str(&p, "100-199"));
        ASSERT_OK(uid_range_add_str(&p, "300-399"));
        ASSERT_OK(uid_range_add_str(&p, "500-599"));
        ASSERT_EQ(uid_range_entries(p), 3U);

        /* Intersect with range that covers all entries */
        ASSERT_OK(uid_range_clip(p, 0, 1000));
        ASSERT_EQ(uid_range_entries(p), 3U);
        ASSERT_EQ(p->entries[0].start, 100U);
        ASSERT_EQ(p->entries[0].nr, 100U);
        ASSERT_EQ(p->entries[1].start, 300U);
        ASSERT_EQ(p->entries[1].nr, 100U);
        ASSERT_EQ(p->entries[2].start, 500U);
        ASSERT_EQ(p->entries[2].nr, 100U);

        /* Intersect with range that excludes first and last entries */
        ASSERT_OK(uid_range_clip(p, 200, 499));
        ASSERT_EQ(uid_range_entries(p), 1U);
        ASSERT_EQ(p->entries[0].start, 300U);
        ASSERT_EQ(p->entries[0].nr, 100U);

        p = uid_range_free(p);

        /* Test partial overlap - trimming from both sides */
        ASSERT_OK(uid_range_add_str(&p, "100-199"));
        ASSERT_OK(uid_range_clip(p, 150, 180));
        ASSERT_EQ(uid_range_entries(p), 1U);
        ASSERT_EQ(p->entries[0].start, 150U);
        ASSERT_EQ(p->entries[0].nr, 31U);

        p = uid_range_free(p);

        /* Test intersection that removes all entries */
        ASSERT_OK(uid_range_add_str(&p, "100-199"));
        ASSERT_OK(uid_range_clip(p, 500, 600));
        ASSERT_TRUE(uid_range_is_empty(p));

        p = uid_range_free(p);

        /* Test invalid min > max */
        ASSERT_OK(uid_range_add_str(&p, "100-199"));
        ASSERT_ERROR(uid_range_clip(p, 200, 100), EINVAL);

        p = uid_range_free(p);

        /* Test with max == UINT32_MAX (should not overflow) */
        ASSERT_OK(uid_range_add_str(&p, "100-199"));
        ASSERT_OK(uid_range_clip(p, 0, UINT32_MAX));
        ASSERT_EQ(uid_range_entries(p), 1U);
        ASSERT_EQ(p->entries[0].start, 100U);
        ASSERT_EQ(p->entries[0].nr, 100U);

        p = uid_range_free(p);

        /* Test with both min and max at extremes */
        ASSERT_OK(uid_range_add_str(&p, "100-199"));
        ASSERT_OK(uid_range_add_str(&p, "500-599"));
        ASSERT_OK(uid_range_clip(p, 150, UINT32_MAX));
        ASSERT_EQ(uid_range_entries(p), 2U);
        ASSERT_EQ(p->entries[0].start, 150U);
        ASSERT_EQ(p->entries[0].nr, 50U);
        ASSERT_EQ(p->entries[1].start, 500U);
        ASSERT_EQ(p->entries[1].nr, 100U);
}

TEST(uid_range_partition) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL;

        /* Single entry that divides evenly */
        ASSERT_OK(uid_range_add_str(&p, "0-299"));
        ASSERT_EQ(uid_range_entries(p), 1U);
        ASSERT_OK(uid_range_partition(p, 100));
        ASSERT_EQ(uid_range_entries(p), 3U);
        ASSERT_EQ(p->entries[0].start, 0U);
        ASSERT_EQ(p->entries[0].nr, 100U);
        ASSERT_EQ(p->entries[1].start, 100U);
        ASSERT_EQ(p->entries[1].nr, 100U);
        ASSERT_EQ(p->entries[2].start, 200U);
        ASSERT_EQ(p->entries[2].nr, 100U);

        p = uid_range_free(p);

        /* Entry with remainder (gets truncated) */
        ASSERT_OK(uid_range_add_str(&p, "0-249"));
        ASSERT_OK(uid_range_partition(p, 100));
        ASSERT_EQ(uid_range_entries(p), 2U);
        ASSERT_EQ(p->entries[0].start, 0U);
        ASSERT_EQ(p->entries[0].nr, 100U);
        ASSERT_EQ(p->entries[1].start, 100U);
        ASSERT_EQ(p->entries[1].nr, 100U);

        p = uid_range_free(p);

        /* Entry smaller than partition size - gets dropped */
        ASSERT_OK(uid_range_add_str(&p, "0-49"));
        ASSERT_OK(uid_range_partition(p, 100));
        ASSERT_TRUE(uid_range_is_empty(p));

        p = uid_range_free(p);

        /* Multiple entries */
        ASSERT_OK(uid_range_add_str(&p, "0-199"));
        ASSERT_OK(uid_range_add_str(&p, "1000-1299"));
        ASSERT_EQ(uid_range_entries(p), 2U);
        ASSERT_OK(uid_range_partition(p, 100));
        ASSERT_EQ(uid_range_entries(p), 5U);
        ASSERT_EQ(p->entries[0].start, 0U);
        ASSERT_EQ(p->entries[0].nr, 100U);
        ASSERT_EQ(p->entries[1].start, 100U);
        ASSERT_EQ(p->entries[1].nr, 100U);
        ASSERT_EQ(p->entries[2].start, 1000U);
        ASSERT_EQ(p->entries[2].nr, 100U);
        ASSERT_EQ(p->entries[3].start, 1100U);
        ASSERT_EQ(p->entries[3].nr, 100U);
        ASSERT_EQ(p->entries[4].start, 1200U);
        ASSERT_EQ(p->entries[4].nr, 100U);

        p = uid_range_free(p);

        /* Partition size of 1 */
        ASSERT_OK(uid_range_add_str(&p, "100-102"));
        ASSERT_OK(uid_range_partition(p, 1));
        ASSERT_EQ(uid_range_entries(p), 3U);
        ASSERT_EQ(p->entries[0].start, 100U);
        ASSERT_EQ(p->entries[0].nr, 1U);
        ASSERT_EQ(p->entries[1].start, 101U);
        ASSERT_EQ(p->entries[1].nr, 1U);
        ASSERT_EQ(p->entries[2].start, 102U);
        ASSERT_EQ(p->entries[2].nr, 1U);
}

TEST(uid_range_copy) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL, *copy = NULL;

        /* Copy NULL range */
        ASSERT_OK(uid_range_copy(NULL, &copy));
        ASSERT_TRUE(uid_range_is_empty(copy));

        copy = uid_range_free(copy);

        /* Copy empty range */
        p = new0(UIDRange, 1);
        ASSERT_NOT_NULL(p);
        ASSERT_OK(uid_range_copy(p, &copy));
        ASSERT_NOT_NULL(copy);
        ASSERT_TRUE(uid_range_is_empty(copy));

        p = uid_range_free(p);
        copy = uid_range_free(copy);

        /* Copy range with entries */
        ASSERT_OK(uid_range_add_str(&p, "100-199"));
        ASSERT_OK(uid_range_add_str(&p, "300-399"));
        ASSERT_OK(uid_range_copy(p, &copy));
        ASSERT_TRUE(uid_range_equal(p, copy));

        /* Verify it's a deep copy - modifying original doesn't affect copy */
        ASSERT_OK(uid_range_add_str(&p, "500-599"));
        ASSERT_FALSE(uid_range_equal(p, copy));
        ASSERT_EQ(uid_range_entries(copy), 2U);
}

TEST(uid_range_remove) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL;

        /* Build a range: 100-199 */
        ASSERT_OK(uid_range_add_str(&p, "100-199"));

        /* Remove with size 0 - no-op */
        ASSERT_OK(uid_range_remove(p, 150, 0));
        ASSERT_EQ(uid_range_entries(p), 1U);
        ASSERT_EQ(p->entries[0].start, 100U);
        ASSERT_EQ(p->entries[0].nr, 100U);

        /* Remove range that doesn't overlap - no change */
        ASSERT_OK(uid_range_remove(p, 0, 50));
        ASSERT_EQ(uid_range_entries(p), 1U);
        ASSERT_EQ(p->entries[0].start, 100U);
        ASSERT_EQ(p->entries[0].nr, 100U);

        ASSERT_OK(uid_range_remove(p, 300, 50));
        ASSERT_EQ(uid_range_entries(p), 1U);
        ASSERT_EQ(p->entries[0].start, 100U);
        ASSERT_EQ(p->entries[0].nr, 100U);

        /* Remove from the start of the entry */
        ASSERT_OK(uid_range_remove(p, 100, 10));
        ASSERT_EQ(uid_range_entries(p), 1U);
        ASSERT_EQ(p->entries[0].start, 110U);
        ASSERT_EQ(p->entries[0].nr, 90U);

        /* Remove from the end of the entry */
        ASSERT_OK(uid_range_remove(p, 190, 10));
        ASSERT_EQ(uid_range_entries(p), 1U);
        ASSERT_EQ(p->entries[0].start, 110U);
        ASSERT_EQ(p->entries[0].nr, 80U);

        /* Remove from the middle - splits the entry */
        ASSERT_OK(uid_range_remove(p, 140, 20));
        ASSERT_EQ(uid_range_entries(p), 2U);
        ASSERT_EQ(p->entries[0].start, 110U);
        ASSERT_EQ(p->entries[0].nr, 30U);
        ASSERT_EQ(p->entries[1].start, 160U);
        ASSERT_EQ(p->entries[1].nr, 30U);

        p = uid_range_free(p);

        /* Remove entire entry */
        ASSERT_OK(uid_range_add_str(&p, "100-199"));
        ASSERT_OK(uid_range_remove(p, 100, 100));
        ASSERT_TRUE(uid_range_is_empty(p));

        p = uid_range_free(p);

        /* Remove range larger than entry */
        ASSERT_OK(uid_range_add_str(&p, "100-199"));
        ASSERT_OK(uid_range_remove(p, 50, 200));
        ASSERT_TRUE(uid_range_is_empty(p));

        p = uid_range_free(p);

        /* Remove affecting multiple entries */
        ASSERT_OK(uid_range_add_str(&p, "100-199"));
        ASSERT_OK(uid_range_add_str(&p, "300-399"));
        ASSERT_OK(uid_range_add_str(&p, "500-599"));
        ASSERT_EQ(uid_range_entries(p), 3U);

        /* Remove range spanning the middle entry completely and trimming others */
        ASSERT_OK(uid_range_remove(p, 150, 400));
        ASSERT_EQ(uid_range_entries(p), 2U);
        ASSERT_EQ(p->entries[0].start, 100U);
        ASSERT_EQ(p->entries[0].nr, 50U);
        ASSERT_EQ(p->entries[1].start, 550U);
        ASSERT_EQ(p->entries[1].nr, 50U);
}

TEST(uid_range_translate) {
        _cleanup_(uid_range_freep) UIDRange *o = NULL, *i = NULL;
        uid_t uid;

        ASSERT_OK(uid_range_add_str_full(&o, "200-299", /* coalesce= */ false));
        ASSERT_OK(uid_range_add_str_full(&i, "100-199", /* coalesce= */ false));
        ASSERT_OK(uid_range_translate(o, i, 250, &uid));
        ASSERT_EQ(uid, 150U);
        ASSERT_OK(uid_range_translate(i, o, 150, &uid));
        ASSERT_EQ(uid, 250U);

        ASSERT_OK(uid_range_add_str_full(&o, "300-399", /* coalesce= */ false));
        ASSERT_OK(uid_range_add_str_full(&i, "350-449", /* coalesce= */ false));
        ASSERT_OK(uid_range_translate(o, i, 350, &uid));
        ASSERT_EQ(uid, 400U);
        ASSERT_OK(uid_range_translate(i, o, 400, &uid));
        ASSERT_EQ(uid, 350U);

        /* Test translating at range boundaries */
        ASSERT_OK(uid_range_translate(o, i, 200, &uid));
        ASSERT_EQ(uid, 100U);
        ASSERT_OK(uid_range_translate(o, i, 299, &uid));
        ASSERT_EQ(uid, 199U);
        ASSERT_OK(uid_range_translate(o, i, 300, &uid));
        ASSERT_EQ(uid, 350U);
        ASSERT_OK(uid_range_translate(o, i, 399, &uid));
        ASSERT_EQ(uid, 449U);

        /* Test reverse translation at boundaries */
        ASSERT_OK(uid_range_translate(i, o, 100, &uid));
        ASSERT_EQ(uid, 200U);
        ASSERT_OK(uid_range_translate(i, o, 199, &uid));
        ASSERT_EQ(uid, 299U);
        ASSERT_OK(uid_range_translate(i, o, 350, &uid));
        ASSERT_EQ(uid, 300U);
        ASSERT_OK(uid_range_translate(i, o, 449, &uid));
        ASSERT_EQ(uid, 399U);

        /* Test UID not in any range returns ESRCH */
        ASSERT_ERROR(uid_range_translate(o, i, 0, &uid), ESRCH);
        ASSERT_ERROR(uid_range_translate(o, i, 199, &uid), ESRCH);
        ASSERT_ERROR(uid_range_translate(o, i, 400, &uid), ESRCH);
        ASSERT_ERROR(uid_range_translate(i, o, 0, &uid), ESRCH);
        ASSERT_ERROR(uid_range_translate(i, o, 99, &uid), ESRCH);
        ASSERT_ERROR(uid_range_translate(i, o, 200, &uid), ESRCH);
        ASSERT_ERROR(uid_range_translate(i, o, 349, &uid), ESRCH);
        ASSERT_ERROR(uid_range_translate(i, o, 450, &uid), ESRCH);

        o = uid_range_free(o);
        i = uid_range_free(i);

        /* Test with single-element ranges */
        ASSERT_OK(uid_range_add_str_full(&o, "1000", /* coalesce= */ false));
        ASSERT_OK(uid_range_add_str_full(&i, "5000", /* coalesce= */ false));
        ASSERT_OK(uid_range_translate(o, i, 1000, &uid));
        ASSERT_EQ(uid, 5000U);
        ASSERT_OK(uid_range_translate(i, o, 5000, &uid));
        ASSERT_EQ(uid, 1000U);
        ASSERT_ERROR(uid_range_translate(o, i, 999, &uid), ESRCH);
        ASSERT_ERROR(uid_range_translate(o, i, 1001, &uid), ESRCH);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
