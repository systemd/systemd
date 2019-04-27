/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdlib.h>

#include "pager.h"
#include "selinux-util.h"
#include "spawn-ask-password-agent.h"
#include "spawn-polkit-agent.h"
#include "static-destruct.h"
#include "util.h"

#define _DEFINE_MAIN_FUNCTION(intro, impl, ret)                         \
        int main(int argc, char *argv[]) {                              \
                int r;                                                  \
                save_argc_argv(argc, argv);                             \
                intro;                                                  \
                r = impl;                                               \
                ask_password_agent_close();                             \
                polkit_agent_close();                                   \
                pager_close();                                          \
                mac_selinux_finish();                                   \
                static_destruct();                                      \
                return ret;                                             \
        }

/* Negative return values from impl are mapped to EXIT_FAILURE, and
 * everything else means success! */
#define DEFINE_MAIN_FUNCTION(impl)                                      \
        _DEFINE_MAIN_FUNCTION(,impl(argc, argv), r < 0 ? EXIT_FAILURE : EXIT_SUCCESS)

/* Zero is mapped to EXIT_SUCCESS, negative values are mapped to EXIT_FAILURE,
 * and positive values are propagated.
 * Note: "true" means failure! */
#define DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(impl)                \
        _DEFINE_MAIN_FUNCTION(,impl(argc, argv), r < 0 ? EXIT_FAILURE : r)
