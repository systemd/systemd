/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "binfmt-util.h"
#include "tests.h"

TEST(binfmt_mounted) {
        ASSERT_OK(binfmt_mounted());
}

DEFINE_TEST_MAIN(LOG_DEBUG);
