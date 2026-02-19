/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "option-parser.h"

int option_parse(
                const char *optstring,
                const struct option options[],
                int argc,
                char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        r = getopt_long(argc, argv, optstring, options, NULL);
        if (r == '?')  /* Unknown option or missing argument */
                return -EINVAL;
        if (r < 0)     /* End of option processing */
                return 0;
        assert(r >= OPTION_VALUE_MIN);
        return r;      /* One of the (positive) enum values */
}
