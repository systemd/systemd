/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdlib.h>

#include "sd-daemon.h"

#include "argv-util.h"
#include "pager.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "spawn-ask-password-agent.h"
#include "spawn-polkit-agent.h"
#include "static-destruct.h"

#define _DEFINE_MAIN_FUNCTION(intro, impl, result_to_exit_status, result_to_return_value) \
        int main(int argc, char *argv[]) {                              \
                int r;                                                  \
                assert_se(argc > 0 && !isempty(argv[0]));               \
                save_argc_argv(argc, argv);                             \
                intro;                                                  \
                r = impl;                                               \
                if (r < 0)                                              \
                        (void) sd_notifyf(0, "ERRNO=%i", -r);           \
                (void) sd_notifyf(0, "EXIT_STATUS=%i",                  \
                                  result_to_exit_status(r));            \
                ask_password_agent_close();                             \
                polkit_agent_close();                                   \
                pager_close();                                          \
                mac_selinux_finish();                                   \
                static_destruct();                                      \
                return result_to_return_value(r);                       \
        }

static inline int fail_on_negative(int result) {
        return result < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* Negative return values from impl are mapped to EXIT_FAILURE, and
 * everything else means success! */
#define DEFINE_MAIN_FUNCTION(impl)                                      \
        _DEFINE_MAIN_FUNCTION(,impl(argc, argv), fail_on_negative, fail_on_negative)

static inline int fail_on_nonzero(int result) {
        return result < 0 ? EXIT_FAILURE : result;
}

/* Zero is mapped to EXIT_SUCCESS, negative values are mapped to EXIT_FAILURE,
 * and positive values are propagated.
 * Note: "true" means failure! */
#define DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(impl)                \
        _DEFINE_MAIN_FUNCTION(,impl(argc, argv), fail_on_nonzero, fail_on_nonzero)

static inline int raise_or_exit(int ret) {
        if (ret < 0)
                return EXIT_FAILURE;
        if (ret == 0)
                return EXIT_SUCCESS;
        if (!SIGNAL_VALID(ret))
                return EXIT_FAILURE;
        if (raise(ret) < 0)
                return EXIT_FAILURE;
        assert_not_reached();
}

/* Negative return values from impl are mapped to EXIT_FAILURE, zero is mapped to EXIT_SUCCESS,
 * and raise if a positive signal is returned from impl. */
#define DEFINE_MAIN_FUNCTION_WITH_POSITIVE_SIGNAL(impl)                 \
        _DEFINE_MAIN_FUNCTION(,impl(argc, argv), fail_on_negative, raise_or_exit)
