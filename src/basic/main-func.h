/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdlib.h>

/* Negative return values from impl are mapped to EXIT_FAILURE, and
 * everything else means success! */
#define DEFINE_MAIN_FUNCTION(impl)                                      \
        int main(int argc, char *argv[]) {                              \
                int r;                                                  \
                r = impl(argc, argv);                                   \
                return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;             \
        }

/* Zero is mapped to EXIT_SUCCESS, and both negative and positive values
 * are mapped to EXIT_FAILURE.
 * Note: this means "true" maps to EXIT_FAILURE. */
#define DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(impl)                \
        int main(int argc, char *argv[]) {                              \
                int r;                                                  \
                r = impl(argc, argv);                                   \
                return r != 0 ? EXIT_FAILURE : EXIT_SUCCESS;            \
        }
