/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "shared-forward.h"

/* Options can be A-Z, a-z, 0-9. 0 happens to be the first in ASCII. */
#define OPTION_VALUE_MIN '0'

int option_parse(
                const char* optstring,
                const struct option *options,
                int argc,
                char *argv[]);

/* Iterate over options. */
#define FOREACH_OPTION(opt, argc, argv, on_error)                               \
        for (int opt; (opt = option_parse(OPTSTRING, options, argc, argv)); )   \
                if (opt < 0) {                                                  \
                        on_error;                                               \
                        break;                                                  \
                } else if (opt < OPTION_VALUE_MIN)                              \
                        break;                                                  \
                else
