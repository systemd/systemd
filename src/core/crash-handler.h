/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum CrashAction {
        CRASH_FREEZE,
        CRASH_REBOOT,
        CRASH_POWEROFF,
        _CRASH_ACTION_MAX,
        _CRASH_ACTION_INVALID = -EINVAL,
} CrashAction;

const char* crash_action_to_string(CrashAction action);
CrashAction crash_action_from_string(const char *action);

_noreturn_ void freeze_or_exit_or_reboot(void);
void install_crash_handler(void);
