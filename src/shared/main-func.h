/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdlib.h>

#if HAVE_VALGRIND_VALGRIND_H
#  include <valgrind/valgrind.h>
#endif

#include "signal-util.h"
#include "static-destruct.h"

typedef int (*MainIntroFunction)(int, char*[], void*);
typedef int (*MainImplFunction)(int, char*[], void*);
typedef int (*MainResultMapFunction)(int);

/* static_destruct() has to be in the same linking unit as the variables to destroy so we pass the function
 * as an argument instead of calling it directly. */
int _define_main_function_impl(
                int argc,
                char *argv[],
                MainIntroFunction intro,
                MainImplFunction impl,
                MainResultMapFunction result_to_exit_status,
                MainResultMapFunction result_to_return_value,
                typeof(static_destruct) _static_destruct,
                void *userdata);

#define _DEFINE_MAIN_FUNCTION(intro, impl, result_to_exit_status, result_to_return_value, userdata) \
        int main(int argc, char *argv[]) {                                                          \
                return _define_main_function_impl(                                                  \
                                argc,                                                               \
                                argv,                                                               \
                                intro,                                                              \
                                impl,                                                               \
                                result_to_exit_status,                                              \
                                result_to_return_value,                                             \
                                static_destruct,                                                    \
                                userdata);                                                          \
        }

static inline int exit_failure_if_negative(int result) {
        return result < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

static inline int noop_intro(int argc, char *argv[], void *userdata) {
        return 0;
}

typedef int (*ForwardRunFunction)(int, char*[]);

static inline int forward_impl(int argc, char *argv[], void *userdata) {
        ForwardRunFunction forward = ASSERT_PTR(userdata);
        return forward(argc, argv);
}

/* Negative return values from impl are mapped to EXIT_FAILURE, and
 * everything else means success! */
#define DEFINE_MAIN_FUNCTION(impl)                                      \
        _DEFINE_MAIN_FUNCTION(noop_intro, forward_impl, exit_failure_if_negative, exit_failure_if_negative, (ForwardRunFunction) impl)

static inline int exit_failure_if_nonzero(int result) {
        return result < 0 ? EXIT_FAILURE : result;
}

/* Zero is mapped to EXIT_SUCCESS, negative values are mapped to EXIT_FAILURE,
 * and positive values are propagated.
 * Note: "true" means failure! */
#define DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(impl)                \
        _DEFINE_MAIN_FUNCTION(noop_intro, forward_impl, exit_failure_if_nonzero, exit_failure_if_nonzero, (ForwardRunFunction) impl)

int raise_or_exit_status(int ret);

/* Negative return values from impl are mapped to EXIT_FAILURE, zero is mapped to EXIT_SUCCESS,
 * and raise if a positive signal is returned from impl. */
#define DEFINE_MAIN_FUNCTION_WITH_POSITIVE_SIGNAL(impl)                 \
        _DEFINE_MAIN_FUNCTION(noop_intro, forward_impl, exit_failure_if_negative, raise_or_exit_status, (ForwardRunFunction) impl)
