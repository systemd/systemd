/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-list.h"
#include "tests.h"

#include "errno-to-name.inc"

TEST(errno_name_no_fallback) {
        ASSERT_NULL(errno_names[0]);
        ASSERT_NULL(errno_name_no_fallback(0));

        for (size_t i = 0; i < ELEMENTSOF(errno_names); i++)
                if (errno_names[i]) {
                        const char *mapped = errno_name_no_fallback(i);

                        if (mapped)
                                /* glibc might not know some errno names.
                                 * This is not an error. */
                                ASSERT_STREQ(mapped, errno_names[i]);

                        assert_se(errno_from_name(errno_names[i]) == (int) i);
                }

#ifdef ECANCELLED
        /* ECANCELLED is an alias of ECANCELED. */
        ASSERT_STREQ(errno_name_no_fallback(ECANCELLED), "ECANCELED");
#endif
        ASSERT_STREQ(errno_name_no_fallback(ECANCELED), "ECANCELED");

#ifdef EREFUSED
        /* EREFUSED is an alias of ECONNREFUSED. */
        ASSERT_STREQ(errno_name_no_fallback(EREFUSED), "ECONNREFUSED");
#endif
        ASSERT_STREQ(errno_name_no_fallback(ECONNREFUSED), "ECONNREFUSED");
}

TEST(errno_name_full) {
        char buf[ERRNO_NAME_BUF_LEN];

        ASSERT_STREQ(errno_name(0, buf), "0");
        ASSERT_STREQ(errno_name(EPERM, buf), "EPERM");
        ASSERT_STREQ(errno_name(ENOENT, buf), "ENOENT");
        ASSERT_STREQ(errno_name(200, buf), "200");
        ASSERT_STREQ(errno_name(-200, buf), "200");
}

TEST(ERRNO_NAME_FULL) {
        ASSERT_STREQ(ERRNO_NAME(0), "0");
        ASSERT_STREQ(ERRNO_NAME(EPERM), "EPERM");
        ASSERT_STREQ(ERRNO_NAME(ENOENT), "ENOENT");
        ASSERT_STREQ(ERRNO_NAME(200), "200");
        ASSERT_STREQ(ERRNO_NAME(-200), "200");

        int x = 0;
        ASSERT_STREQ(ERRNO_NAME(++x), "EPERM");  /* Confirm that eval happens just once. */
        ASSERT_EQ(x, 1);
}

DEFINE_TEST_MAIN(LOG_INFO);
