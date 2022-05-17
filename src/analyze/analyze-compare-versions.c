/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "analyze-compare-versions.h"
#include "macro.h"
#include "string-util.h"
#include "strv.h"

int verb_compare_versions(int argc, char *argv[], void *userdata) {
        int r;

        assert(argc == 3 || argc == 4);
        assert(argv);

        if (argc == 3) {
                r = strverscmp_improved(ASSERT_PTR(argv[1]), ASSERT_PTR(argv[2]));
                printf("%s %s %s\n",
                       argv[1],
                       r < 0 ? "<" : r > 0 ? ">" : "==",
                       argv[2]);

                /* This matches the exit convention used by rpmdev-vercmp.
                 * We don't use named values because 11 and 12 don't have names. */
                return r < 0 ? 12 : r > 0 ? 11 : 0;

        } else {
                const char *op = ASSERT_PTR(argv[2]);

                r = strverscmp_improved(ASSERT_PTR(argv[1]), ASSERT_PTR(argv[3]));

                if (STR_IN_SET(op, "lt", "<"))
                        return r < 0 ? EXIT_SUCCESS : EXIT_FAILURE;
                if (STR_IN_SET(op, "le", "<="))
                        return r <= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
                if (STR_IN_SET(op, "eq", "=="))
                        return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
                if (STR_IN_SET(op, "ne", "!="))
                        return r != 0 ? EXIT_SUCCESS : EXIT_FAILURE;
                if (STR_IN_SET(op, "ge", ">="))
                        return r >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
                if (STR_IN_SET(op, "gt", ">"))
                        return r > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Unknown operator \"%s\".", op);
        }
}
