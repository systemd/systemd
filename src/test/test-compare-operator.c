/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "compare-operator.h"
#include "tests.h"

TEST(parse_compare_operator) {
        const char *str_a = "<>version";
        assert_se(parse_compare_operator(&str_a, 0) == COMPARE_UNEQUAL);
        const char *str_b = "$=version";
        assert_se(parse_compare_operator(&str_b, 0) == _COMPARE_OPERATOR_INVALID);
        assert_se(parse_compare_operator(&str_b, COMPARE_ALLOW_FNMATCH) == COMPARE_FNMATCH_EQUAL);
        const char *str_c = "eq oranges";
        assert_se(parse_compare_operator(&str_c, 0) == _COMPARE_OPERATOR_INVALID);
        assert_se(parse_compare_operator(&str_c, COMPARE_ALLOW_TEXTUAL) == COMPARE_EQUAL);
        const char *str_d = "";
        assert_se(parse_compare_operator(&str_d, 0) == _COMPARE_OPERATOR_INVALID);
        const char *str_e = "!=!="; /* parse_compare_operator() moves the pointer */
        assert_se(parse_compare_operator(&str_e, COMPARE_EQUAL_BY_STRING) == COMPARE_STRING_UNEQUAL);
        assert_se(parse_compare_operator(&str_e, 0) == COMPARE_UNEQUAL);
        assert_se(parse_compare_operator(&str_e, 0) == _COMPARE_OPERATOR_INVALID);
}

TEST(test_order) {
        assert_se(!test_order(5, COMPARE_LOWER));
        assert_se(!test_order(5, COMPARE_LOWER_OR_EQUAL));
        assert_se(!test_order(5, COMPARE_EQUAL));
        assert_se(test_order(5, COMPARE_UNEQUAL));
        assert_se(test_order(5, COMPARE_GREATER_OR_EQUAL));
        assert_se(test_order(5, COMPARE_GREATER));
        assert_se(test_order(5, COMPARE_STRING_EQUAL) == -EINVAL);
}

TEST(version_or_fnmatch_compare) {
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "locale", "locale"));
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_UNEQUAL, "locale", "LOCALE"));
        assert_se(version_or_fnmatch_compare(COMPARE_FNMATCH_EQUAL, "locaale", "loc*le"));
        assert_se(version_or_fnmatch_compare(COMPARE_FNMATCH_UNEQUAL, "locaale", "loc?le"));
        assert_se(version_or_fnmatch_compare(COMPARE_GREATER, "local512", "local256"));
        assert_se(version_or_fnmatch_compare(COMPARE_LOWER, "local52", "local256"));
        assert_se(version_or_fnmatch_compare(_COMPARE_OPERATOR_MAX, "local512", "local256") == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);
