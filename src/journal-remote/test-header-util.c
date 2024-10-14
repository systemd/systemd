/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "header-util.h"
#include "tests.h"

TEST(strv_header_replace_consume) {
        _cleanup_strv_free_ char **headers = NULL;
        char *value = NULL;

        headers = strv_new("Name: Value1", "Other_Name: Value2");
        assert_se(headers);

        value = strdup("NewName: Val");
        assert_se(strv_header_replace_consume(&headers, value));

        ASSERT_STREQ(headers[0], headers[0]);
        ASSERT_STREQ(headers[1], headers[1]);
        ASSERT_STREQ(headers[2], value);
        assert_se(strv_length(headers) == 3);

        value = strdup("Name: Rewrite");
        strv_header_replace_consume(&headers, value);
        ASSERT_STREQ(headers[0], value);
        assert_se(strv_length(headers) == 3);

        value = strdup("InvalidN@me: test");
        assert_se(strv_header_replace_consume(&headers, value));
        assert_se(strv_length(headers) == 3);
}

TEST(header_is_valid) {
        assert_se(header_is_valid("Name: Value1"));
        assert_se(header_is_valid("Other_Name: Value2"));
        assert_se(!header_is_valid("N@me: Val"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
