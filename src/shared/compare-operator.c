/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>

#include "compare-operator.h"
#include "string-util.h"

CompareOperator parse_compare_operator(const char **s, bool allow_fnmatch) {
        static const char *const prefix[_COMPARE_OPERATOR_MAX] = {
                [COMPARE_FNMATCH_EQUAL] = "=$",
                [COMPARE_FNMATCH_UNEQUAL] = "!=$",

                [COMPARE_LOWER_OR_EQUAL] = "<=",
                [COMPARE_GREATER_OR_EQUAL] = ">=",
                [COMPARE_LOWER] = "<",
                [COMPARE_GREATER] = ">",
                [COMPARE_EQUAL] = "=",
                [COMPARE_UNEQUAL] = "!=",
        };

        for (CompareOperator i = 0; i < _COMPARE_OPERATOR_MAX; i++) {
                const char *e;

                e = startswith(*s, prefix[i]);
                if (e) {
                        if (!allow_fnmatch && COMPARE_OPERATOR_IS_FNMATCH(i))
                                break;
                        *s = e;
                        return i;
                }
        }

        return _COMPARE_OPERATOR_INVALID;
}

int test_order(int k, CompareOperator op) {

        switch (op) {

        case COMPARE_LOWER:
                return k < 0;

        case COMPARE_LOWER_OR_EQUAL:
                return k <= 0;

        case COMPARE_EQUAL:
                return k == 0;

        case COMPARE_UNEQUAL:
                return k != 0;

        case COMPARE_GREATER_OR_EQUAL:
                return k >= 0;

        case COMPARE_GREATER:
                return k > 0;

        default:
                return -EINVAL;
        }
}

int version_or_fnmatch_compare(
                CompareOperator op,
                const char *a,
                const char *b) {

        switch (op) {

        case COMPARE_FNMATCH_EQUAL:
                return fnmatch(b, a, FNM_EXTMATCH) != FNM_NOMATCH;

        case COMPARE_FNMATCH_UNEQUAL:
                return fnmatch(b, a, FNM_EXTMATCH) == FNM_NOMATCH;

        case _COMPARE_OPERATOR_ORDER_FIRST..._COMPARE_OPERATOR_ORDER_LAST:
                return test_order(strverscmp_improved(a, b), op);

        default:
                return -EINVAL;
        }
}
