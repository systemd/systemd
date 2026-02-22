/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

typedef enum CrashAction {
        CRASH_FREEZE,
        CRASH_REBOOT,
        CRASH_POWEROFF,
        _CRASH_ACTION_MAX,
        _CRASH_ACTION_INVALID = -EINVAL,
} CrashAction;

DECLARE_STRING_TABLE_LOOKUP(crash_action, CrashAction);

_noreturn_ void freeze_or_exit_or_reboot(void);
void install_crash_handler(void);
