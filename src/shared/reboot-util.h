/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/reboot.h>       /* IWYU pragma: export */
#include <sys/reboot.h>         /* IWYU pragma: export */

#include "forward.h"

/* glibc defines the reboot() API call, which is a wrapper around the system call of the same name, but
 * without the extra "arg" parameter. Since we need that parameter for some calls, let's add a "raw" wrapper
 * that is defined the same way, except it takes the additional argument. */
int raw_reboot(int cmd, const void *arg);

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
