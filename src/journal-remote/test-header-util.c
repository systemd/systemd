/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "header-util.h"
#include "tests.h"

TEST(strv_header_replace_consume) {
        _cleanup_strv_free_ char **headers = NULL;
        _cleanup_free_ char *in;
        _cleanup_free_ char *out;

        headers = strv_new("Name: Value1", "Other_Name: Value2");
        ASSERT_NOT_NULL(headers);

        in = strdup("NewName: Val");
        ASSERT_NOT_NULL(in);

        out = strdup(in);
        ASSERT_NOT_NULL(out);

        ASSERT_OK(strv_header_replace_consume(&headers, TAKE_PTR(in)));

        ASSERT_STREQ(headers[0], headers[0]);
        ASSERT_STREQ(headers[1], headers[1]);
        ASSERT_STREQ(headers[2], out);

        ASSERT_TRUE(strv_length(headers) == 3);

        in = strdup("Name: Rewrite");
        out = strdup(in);
        strv_header_replace_consume(&headers, TAKE_PTR(in));
        ASSERT_STREQ(headers[0], out);
        ASSERT_TRUE(strv_length(headers) == 3);

        in = strdup("InvalidN@me: test");
        ASSERT_ERROR(strv_header_replace_consume(&headers, TAKE_PTR(in)), EINVAL);
        ASSERT_TRUE(strv_length(headers) == 3);
}

TEST(header_is_valid) {
        ASSERT_TRUE(header_is_valid("Name: Value1"));
        ASSERT_TRUE(header_is_valid("Other_Name: Value2"));
        ASSERT_FALSE(header_is_valid("N@me: Val"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
