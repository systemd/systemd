/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdbool.h>

typedef enum CrashAction {
        CRASH_FREEZE,
        CRASH_REBOOT,
        CRASH_POWEROFF,
        _CRASH_ACTION_MAX,
        _CRASH_ACTION_INVALID = -EINVAL,
} CrashAction;

const char* crash_action_to_string(CrashAction action);
CrashAction crash_action_from_string(const char *action);

extern bool arg_dump_core;
extern int arg_crash_chvt;
extern bool arg_crash_shell;
extern CrashAction arg_crash_action;
