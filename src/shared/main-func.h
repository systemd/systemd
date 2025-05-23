/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "static-destruct.h"    /* IWYU pragma: keep */

void main_prepare(int argc, char *argv[]);

void main_finalize(int r, int exit_status);

#define _DEFINE_MAIN_FUNCTION(intro, impl, result_to_exit_status, result_to_return_value) \
        int main(int argc, char *argv[]) {                              \
                int r;                                                  \
                main_prepare(argc, argv);                               \
                intro;                                                  \
                r = impl;                                               \
                main_finalize(r, result_to_exit_status(r));             \
                static_destruct();                                      \
                return result_to_return_value(r);                       \
        }

int exit_failure_if_negative(int result);

/* Negative return values from impl are mapped to EXIT_FAILURE, and
 * everything else means success! */
#define DEFINE_MAIN_FUNCTION(impl)                                      \
        _DEFINE_MAIN_FUNCTION(,impl(argc, argv), exit_failure_if_negative, exit_failure_if_negative)

int exit_failure_if_nonzero(int result);

/* Zero is mapped to EXIT_SUCCESS, negative values are mapped to EXIT_FAILURE,
 * and positive values are propagated.
 * Note: "true" means failure! */
#define DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(impl)                \
        _DEFINE_MAIN_FUNCTION(,impl(argc, argv), exit_failure_if_nonzero, exit_failure_if_nonzero)

int raise_or_exit_status(int ret);

/* Negative return values from impl are mapped to EXIT_FAILURE, zero is mapped to EXIT_SUCCESS,
 * and raise if a positive signal is returned from impl. */
#define DEFINE_MAIN_FUNCTION_WITH_POSITIVE_SIGNAL(impl)                 \
        _DEFINE_MAIN_FUNCTION(,impl(argc, argv), exit_failure_if_negative, raise_or_exit_status)
