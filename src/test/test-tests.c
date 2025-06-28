/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"

TEST(ASSERT_OK_OR) {
        ASSERT_OK_OR(0, -EINVAL, -EUCLEAN);
        ASSERT_OK_OR(99, -EINVAL, -EUCLEAN);
        ASSERT_OK_OR(-EINVAL, -EINVAL, -EUCLEAN);
        ASSERT_OK_OR(-EUCLEAN, -EUCLEAN);
        ASSERT_OK_OR(-1, -EPERM);
}

DEFINE_TEST_MAIN(LOG_INFO);
