/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

bool reboot_parameter_is_valid(const char *parameter);
int update_reboot_parameter_and_warn(const char *parameter, bool keep);

typedef enum RebootFlags {
        REBOOT_LOG      = 1 << 0, /* log about what we are going to do and all errors */
        REBOOT_DRY_RUN  = 1 << 1, /* return 0 right before actually doing the reboot */
        REBOOT_FALLBACK = 1 << 2, /* fall back to plain reboot() if argument-based reboot doesn't work, isn't configured or doesn't apply otherwise */
} RebootFlags;

int read_reboot_parameter(char **parameter);
int reboot_with_parameter(RebootFlags flags);

bool shall_restore_state(void);

bool kexec_loaded(void);

int create_shutdown_run_nologin_or_warn(void);
