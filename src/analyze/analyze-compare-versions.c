/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "analyze-compare-versions.h"
#include "macro.h"
#include "string-util.h"

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

                /* This matches the exit convention used by rpmdev-vercmp. */
                return r < 0 ? 12 : r > 0 ? 11 : 0;

        } else {
                const char *op = ASSERT_PTR(argv[2]);

                r = strverscmp_improved(ASSERT_PTR(argv[1]), ASSERT_PTR(argv[3]));

                if (streq(op, "lt"))
                        return r < 0 ? 0 : 1;
                if (streq(op, "le"))
                        return r <= 0 ? 0 : 1;
                if (streq(op, "eq"))
                        return r == 0 ? 0 : 1;
                if (streq(op, "ne"))
                        return r != 0 ? 0 : 1;
                if (streq(op, "ge"))
                        return r >= 0 ? 0 : 1;
                if (streq(op, "gt"))
                        return r > 0 ? 0 : 1;
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Unknown operator \"%s\".", op);
        }
}
