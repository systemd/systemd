/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hashmap.h"
#include "journal-header-util.h"
#include "tests.h"

TEST(header_put) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *headers = NULL;

        ASSERT_EQ(header_put(&headers, "NewName", "Val"), 1);
        ASSERT_EQ(header_put(&headers, "Name", "FirstName"), 1);
        ASSERT_EQ(header_put(&headers, "Name", "Override"), 1);
        ASSERT_EQ(header_put(&headers, "Name", "FirstName"), 0);
        ASSERT_ERROR(header_put(&headers, "InvalidN@me", "test"), EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
