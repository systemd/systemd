/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>

#include "compare-operator.h"
#include "string-util.h"

CompareOperator parse_compare_operator(const char **s, CompareOperatorParseFlags flags) {
        static const struct {
                CompareOperator op;
                const char *str;
                CompareOperatorParseFlags valid_mask; /* If this operator appears when flags in mask not set, fail */
                CompareOperatorParseFlags need_mask;  /* Skip over this operattor when flags in mask not set */
        } table[] = {
                { COMPARE_FNMATCH_EQUAL,    "$=",  .valid_mask = COMPARE_ALLOW_FNMATCH   },
                { COMPARE_FNMATCH_UNEQUAL,  "!$=", .valid_mask = COMPARE_ALLOW_FNMATCH   },

                { COMPARE_UNEQUAL,          "<>"                                         },
                { COMPARE_LOWER_OR_EQUAL,   "<="                                         },
                { COMPARE_GREATER_OR_EQUAL, ">="                                         },
                { COMPARE_LOWER,            "<"                                          },
                { COMPARE_GREATER,          ">"                                          },
                { COMPARE_EQUAL,            "=="                                         },
                { COMPARE_STRING_EQUAL,     "=",   .need_mask = COMPARE_EQUAL_BY_STRING  },
                { COMPARE_EQUAL,            "="                                          },
                { COMPARE_STRING_UNEQUAL,   "!=",  .need_mask = COMPARE_EQUAL_BY_STRING  },
                { COMPARE_UNEQUAL,          "!="                                         },

                { COMPARE_LOWER,            "lt",  .valid_mask = COMPARE_ALLOW_TEXTUAL   },
                { COMPARE_LOWER_OR_EQUAL,   "le",  .valid_mask = COMPARE_ALLOW_TEXTUAL   },
                { COMPARE_EQUAL,            "eq",  .valid_mask = COMPARE_ALLOW_TEXTUAL   },
                { COMPARE_UNEQUAL,          "ne",  .valid_mask = COMPARE_ALLOW_TEXTUAL   },
                { COMPARE_GREATER_OR_EQUAL, "ge",  .valid_mask = COMPARE_ALLOW_TEXTUAL   },
                { COMPARE_GREATER,          "gt",  .valid_mask = COMPARE_ALLOW_TEXTUAL   },
        };

        assert(s);

        if (!*s) /* Hmm, we already reached the end, for example because extract_first_word() and
                  * parse_compare_operator() are use on the same string? */
                return _COMPARE_OPERATOR_INVALID;

        for (size_t i = 0; i < ELEMENTSOF(table); i ++) {
                const char *e;

                if (table[i].need_mask != 0 && !FLAGS_SET(flags, table[i].need_mask))
                        continue;

                e = startswith(*s, table[i].str);
                if (e) {
                        if (table[i].valid_mask != 0 && !FLAGS_SET(flags, table[i].valid_mask))
                                return _COMPARE_OPERATOR_INVALID;

                        *s = e;
                        return table[i].op;
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
        int r;

        switch (op) {

        case COMPARE_STRING_EQUAL:
                return streq_ptr(a, b);

        case COMPARE_STRING_UNEQUAL:
                return !streq_ptr(a, b);

        case COMPARE_FNMATCH_EQUAL:
                r = fnmatch(b, a, 0);
                return r == 0 ? true :
                        r == FNM_NOMATCH ? false : -EINVAL;

        case COMPARE_FNMATCH_UNEQUAL:
                r = fnmatch(b, a, 0);
                return r == FNM_NOMATCH ? true:
                        r == 0 ? false : -EINVAL;

        case _COMPARE_OPERATOR_ORDER_FIRST..._COMPARE_OPERATOR_ORDER_LAST:
                return test_order(strverscmp_improved(a, b), op);

        default:
                return -EINVAL;
        }
}
