/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "compare-operator.h"
#include "tests.h"

TEST(parse_compare_operator) {
        const char *str_a = "<>version";
        ASSERT_EQ(parse_compare_operator(&str_a, /* flags= */ 0), COMPARE_UNEQUAL);
        const char *str_b = "$=version";
        ASSERT_EQ(parse_compare_operator(&str_b, /* flags= */ 0), _COMPARE_OPERATOR_INVALID);
        ASSERT_EQ(parse_compare_operator(&str_b, COMPARE_ALLOW_FNMATCH), COMPARE_FNMATCH_EQUAL);
        const char *str_c = "eq oranges";
        ASSERT_EQ(parse_compare_operator(&str_c, /* flags= */ 0), _COMPARE_OPERATOR_INVALID);
        ASSERT_EQ(parse_compare_operator(&str_c, COMPARE_ALLOW_TEXTUAL), COMPARE_EQUAL);
        const char *str_d = "";
        ASSERT_EQ(parse_compare_operator(&str_d, /* flags= */ 0), _COMPARE_OPERATOR_INVALID);
        const char *str_e = "!=!="; /* parse_compare_operator() moves the pointer */
        ASSERT_EQ(parse_compare_operator(&str_e, COMPARE_EQUAL_BY_STRING), COMPARE_STRING_UNEQUAL);
        ASSERT_EQ(parse_compare_operator(&str_e, /* flags= */ 0), COMPARE_UNEQUAL);
        ASSERT_EQ(parse_compare_operator(&str_e, /* flags= */ 0), _COMPARE_OPERATOR_INVALID);
}

TEST(test_order) {
        ASSERT_OK_ZERO(test_order(5, COMPARE_LOWER));
        ASSERT_OK_ZERO(test_order(5, COMPARE_LOWER_OR_EQUAL));
        ASSERT_OK_ZERO(test_order(5, COMPARE_EQUAL));
        ASSERT_OK_POSITIVE(test_order(5, COMPARE_UNEQUAL));
        ASSERT_OK_POSITIVE(test_order(5, COMPARE_GREATER_OR_EQUAL));
        ASSERT_OK_POSITIVE(test_order(5, COMPARE_GREATER));
        ASSERT_ERROR(test_order(5, COMPARE_STRING_EQUAL), EINVAL);
}

TEST(version_or_fnmatch_compare) {
        ASSERT_OK_POSITIVE(version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "locale", "locale"));
        ASSERT_OK_POSITIVE(version_or_fnmatch_compare(COMPARE_STRING_UNEQUAL, "locale", "LOCALE"));
        ASSERT_OK_POSITIVE(version_or_fnmatch_compare(COMPARE_FNMATCH_EQUAL, "locaale", "loc*le"));
        ASSERT_OK_POSITIVE(version_or_fnmatch_compare(COMPARE_FNMATCH_UNEQUAL, "locaale", "loc?le"));
        ASSERT_OK_POSITIVE(version_or_fnmatch_compare(COMPARE_GREATER, "local512", "local256"));
        ASSERT_OK_POSITIVE(version_or_fnmatch_compare(COMPARE_LOWER, "local52", "local256"));
        ASSERT_ERROR(version_or_fnmatch_compare(_COMPARE_OPERATOR_MAX, "local512", "local256"), EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);
