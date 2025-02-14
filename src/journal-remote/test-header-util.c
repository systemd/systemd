/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "header-util.h"
#include "tests.h"

static void check_headers_consume(char ***headers, const char *header, int idx) {
        size_t prevLen;
        _cleanup_free_ char *in = NULL;

        prevLen = strv_length(*headers);
        in = strdup(header);
        ASSERT_NOT_NULL(in);
        if (idx >= 0) {
                ASSERT_OK(strv_header_replace_consume(headers, TAKE_PTR(in)));
                ASSERT_STREQ((*headers)[idx], header);
        } else {
                ASSERT_ERROR(strv_header_replace_consume(headers, TAKE_PTR(in)), EINVAL);
                ASSERT_TRUE(strv_length(*headers) == prevLen);
        }
}

TEST(strv_header_replace_consume) {
        _cleanup_strv_free_ char **headers = NULL;

        headers = strv_new("Name: Value1", "Other_Name: Value2");
        ASSERT_NOT_NULL(headers);

        check_headers_consume(&headers, "NewName: Val", 2);
        check_headers_consume(&headers, "Name: Rewrite", 0);
        check_headers_consume(&headers, "InvalidN@me: test", -1);
}

TEST(header_is_valid) {
        ASSERT_TRUE(header_is_valid("Name: Value1"));
        ASSERT_TRUE(header_is_valid("Other_Name: Value2"));
        ASSERT_FALSE(header_is_valid("N@me: Val"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
