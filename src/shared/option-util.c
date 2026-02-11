/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "option-util.h"

int option_parse(
                const char* optstring,
                const struct option *options,
                int argc,
                char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        r = getopt_long(argc, argv, optstring, options, NULL);
        if (r == '?')
                return -EINVAL;
        if (r < 0)
                return 1;
        return r;
}
