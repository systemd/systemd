/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

int update_reboot_parameter_and_warn(const char *parameter);

typedef enum RebootFlags {
        REBOOT_LOG      = 1 << 0, /* log about what we are going to do and all errors */
        REBOOT_DRY_RUN  = 1 << 1, /* return 0 right before actually doing the reboot */
        REBOOT_FALLBACK = 1 << 2, /* fallback to plain reboot() if argument-based reboot doesn't work, isn't configured or doesn't apply otherwise */
} RebootFlags;

int reboot_with_parameter(RebootFlags flags);
