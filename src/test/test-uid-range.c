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

DEFINE_TEST_MAIN(LOG_DEBUG);
