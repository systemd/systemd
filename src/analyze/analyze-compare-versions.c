/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "analyze-compare-versions.h"
#include "compare-operator.h"
#include "macro.h"
#include "string-util.h"
#include "strv.h"

int verb_compare_versions(int argc, char *argv[], void *userdata) {
        int r;

        assert(IN_SET(argc, 3, 4));
        assert(argv);

        if (argc == 3) {
                r = strverscmp_improved(ASSERT_PTR(argv[1]), ASSERT_PTR(argv[2]));
                printf("%s %s %s\n",
                       isempty(argv[1]) ? "''" : argv[1],
                       comparison_operator(r),
                       isempty(argv[2]) ? "''" : argv[2]);

                /* This matches the exit convention used by rpmdev-vercmp.
                 * We don't use named values because 11 and 12 don't have names. */
                return r < 0 ? 12 : r > 0 ? 11 : 0;

        } else {
                const char *op = ASSERT_PTR(argv[2]);
                CompareOperator operator;

                operator = parse_compare_operator(&op, COMPARE_ALLOW_TEXTUAL);
                if (operator < 0 || !isempty(op))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown operator \"%s\".", op);

                r = version_or_fnmatch_compare(operator, ASSERT_PTR(argv[1]), ASSERT_PTR(argv[3]));
                if (r < 0)
                        return log_error_errno(r, "Failed to compare versions: %m");

                return r ? EXIT_SUCCESS : EXIT_FAILURE;
        }
}
