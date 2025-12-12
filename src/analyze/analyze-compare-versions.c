/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "analyze-compare-versions.h"
#include "compare-operator.h"
#include "log.h"
#include "string-util.h"

int verb_compare_versions(int argc, char *argv[], void *userdata) {
        const char *v1 = ASSERT_PTR(argv[1]), *v2 = ASSERT_PTR(argv[argc-1]);
        int r;

        assert(IN_SET(argc, 3, 4));
        assert(argv);

        /* We only output a warning on invalid version strings (instead of failing), since the comparison
         * functions try to handle invalid strings gracefully and it's still interesting to see what the
         * comparison result will be. */
        if (!version_is_valid_versionspec(v1))
                log_warning("Version string 1 contains disallowed characters, they will be treated as separators: %s", v1);
        if (!version_is_valid_versionspec(v2))
                log_warning("Version string 2 contains disallowed characters, they will be treated as separators: %s", v2);

        if (argc == 3) {
                r = strverscmp_improved(v1, v2);
                printf("%s %s %s\n",
                       isempty(v1) ? "''" : v1,
                       comparison_operator(r),
                       isempty(v2) ? "''" : v2);

                /* This matches the exit convention used by rpmdev-vercmp.
                 * We don't use named values because 11 and 12 don't have names. */
                return r < 0 ? 12 : r > 0 ? 11 : 0;

        } else {
                const char *op = ASSERT_PTR(argv[2]);
                CompareOperator operator;
                assert(argc == 4);

                operator = parse_compare_operator(&op, COMPARE_ALLOW_TEXTUAL);
                if (operator < 0 || !isempty(op))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown operator \"%s\".", op);

                r = version_or_fnmatch_compare(operator, v1, v2);
                if (r < 0)
                        return log_error_errno(r, "Failed to compare versions: %m");

                return r ? EXIT_SUCCESS : EXIT_FAILURE;
        }
}
