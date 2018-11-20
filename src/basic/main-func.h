/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdlib.h>

#include "static-destruct.h"

/* Negative return values from impl are mapped to EXIT_FAILURE, and
 * everything else means success! */
#define DEFINE_MAIN_FUNCTION(impl)                                      \
        int main(int argc, char *argv[]) {                              \
                int r;                                                  \
                r = impl(argc, argv);                                   \
                static_destruct();                                      \
                return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;             \
        }

/* Zero is mapped to EXIT_SUCCESS, negative values are mapped to EXIT_FAILURE,
 * and postive values are propagated.
 * Note: "true" means failure! */
#define DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(impl)                \
        int main(int argc, char *argv[]) {                              \
                int r;                                                  \
                r = impl(argc, argv);                                   \
                static_destruct();                                      \
                return r < 0 ? EXIT_FAILURE : r;                        \
        }
