/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-list.h"
#include "tests.h"

#include "errno-to-name.inc"

TEST(errno_list) {
        ASSERT_NULL(errno_names[0]);
        ASSERT_NULL(errno_to_name(0));

        for (size_t i = 0; i < ELEMENTSOF(errno_names); i++) {
                if (errno_names[i]) {
                        ASSERT_STREQ(errno_to_name(i), errno_names[i]);
                        assert_se(errno_from_name(errno_names[i]) == (int) i);
                }
        }

#ifdef ECANCELLED
        /* ECANCELLED is an alias of ECANCELED. */
        ASSERT_STREQ(errno_to_name(ECANCELLED), "ECANCELED");
#endif
        ASSERT_STREQ(errno_to_name(ECANCELED), "ECANCELED");

#ifdef EREFUSED
        /* EREFUSED is an alias of ECONNREFUSED. */
        ASSERT_STREQ(errno_to_name(EREFUSED), "ECONNREFUSED");
#endif
        ASSERT_STREQ(errno_to_name(ECONNREFUSED), "ECONNREFUSED");
}

TEST(errno_name_full) {
        char buf[ERRNO_NAME_BUF_LEN];

        ASSERT_STREQ(errno_name_full(0, buf), "0");
        ASSERT_STREQ(errno_name_full(EPERM, buf), "EPERM");
        ASSERT_STREQ(errno_name_full(ENOENT, buf), "ENOENT");
        ASSERT_STREQ(errno_name_full(200, buf), "200");
        ASSERT_STREQ(errno_name_full(-200, buf), "200");
}

TEST(ERRNO_NAME_FULL) {
        ASSERT_STREQ(ERRNO_NAME_FULL(0), "0");
        ASSERT_STREQ(ERRNO_NAME_FULL(EPERM), "EPERM");
        ASSERT_STREQ(ERRNO_NAME_FULL(ENOENT), "ENOENT");
        ASSERT_STREQ(ERRNO_NAME_FULL(200), "200");
        ASSERT_STREQ(ERRNO_NAME_FULL(-200), "200");

        int x = 0;
        ASSERT_STREQ(ERRNO_NAME_FULL(++x), "EPERM");  /* Confirm that eval happens just once. */
        ASSERT_EQ(x, 1);
}

DEFINE_TEST_MAIN(LOG_INFO);
