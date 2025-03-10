/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hashmap.h"
#include "journal-header-util.h"
#include "tests.h"

static void check_header_put(OrderedHashmap **headers, const char *name, const char *value, int expectCode) {
        ASSERT_EQ(header_put(headers, (char *)name, (char *)value), expectCode);
}

TEST(header_put) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *headers = NULL;

        check_header_put(&headers, "NewName", "Val", 1);
        check_header_put(&headers, "Name", "FirstName", 1);
        check_header_put(&headers, "Name", "Override", 1);
        check_header_put(&headers, "Name", "FirstName", 0);
        check_header_put(&headers, "InvalidN@me", "test", 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
