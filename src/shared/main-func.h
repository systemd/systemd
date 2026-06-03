/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"
#include "static-destruct.h"    /* IWYU pragma: keep */

void main_prepare(int argc, char *argv[]);

void main_finalize(int r, int exit_status);

#define _DEFINE_MAIN_FUNCTION(intro, impl, result_to_exit_status)       \
        int main(int argc, char *argv[]) {                              \
                int r, s;                                               \
                main_prepare(argc, argv);                               \
                intro;                                                  \
                r = impl;                                               \
                s = result_to_exit_status(r);                           \
                main_finalize(r, s);                                    \
                static_destruct();                                      \
                return s;                                               \
        }

int exit_failure_if_negative(int result) _const_;

/* Negative return values from impl are mapped to EXIT_FAILURE, and
 * everything else means success! */
#define DEFINE_MAIN_FUNCTION(impl)                                      \
        _DEFINE_MAIN_FUNCTION(, impl(argc, argv), exit_failure_if_negative)

int exit_failure_if_nonzero(int result) _const_;

/* Zero is mapped to EXIT_SUCCESS, negative values are mapped to EXIT_FAILURE,
 * and positive values are propagated.
 * Note: "true" means failure! */
#define DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(impl)                \
        _DEFINE_MAIN_FUNCTION(, impl(argc, argv), exit_failure_if_nonzero)

typedef int (*main_fiber_func_t)(int argc, char *argv[]);

/* Build an sd_event with exit-on-idle enabled, spawn impl as a fiber on it, and run the event loop.
 * Structured concurrency does the rest — when impl returns it must have cancelled and cleaned up
 * everything it spawned, leaving the loop idle so it terminates on its own. The future's result
 * (i.e. impl's return value) is then propagated to the caller. */
int run_main_fiber(int argc, char *argv[], main_fiber_func_t func);

#define DEFINE_MAIN_FUNCTION_FIBER(impl)                                \
        _DEFINE_MAIN_FUNCTION(, run_main_fiber(argc, argv, impl), exit_failure_if_negative)
