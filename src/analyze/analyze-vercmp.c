/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "analyze-vercmp.h"
#include "macro.h"
#include "string-util.h"

int verb_vercmp(int argc, char *argv[], void *userdata) {
        int r;

        assert(argc == 3);
        assert(argv);

        r = strverscmp_improved(ASSERT_PTR(argv[1]), ASSERT_PTR(argv[2]));
        printf("%s %s %s\n",
               argv[1],
               r < 0 ? "<" : r > 0 ? ">" : "==",
               argv[2]);

        /* This matches the exit convention used by rpmdev-vercmp. */
        return r < 0 ? 12 : r > 0 ? 11 : 0;
}
