/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

typedef enum EmergencyAction {
        EMERGENCY_ACTION_NONE,
        EMERGENCY_ACTION_EXIT,
        EMERGENCY_ACTION_EXIT_FORCE,
        _EMERGENCY_ACTION_LAST_USER_ACTION = EMERGENCY_ACTION_EXIT_FORCE,
        EMERGENCY_ACTION_REBOOT,
        EMERGENCY_ACTION_REBOOT_FORCE,
        EMERGENCY_ACTION_REBOOT_IMMEDIATE,
        EMERGENCY_ACTION_POWEROFF,
        EMERGENCY_ACTION_POWEROFF_FORCE,
        EMERGENCY_ACTION_POWEROFF_IMMEDIATE,
        EMERGENCY_ACTION_SOFT_REBOOT,
        EMERGENCY_ACTION_SOFT_REBOOT_FORCE,
        EMERGENCY_ACTION_KEXEC,
        EMERGENCY_ACTION_KEXEC_FORCE,
        EMERGENCY_ACTION_HALT,
        EMERGENCY_ACTION_HALT_FORCE,
        EMERGENCY_ACTION_HALT_IMMEDIATE,
        _EMERGENCY_ACTION_MAX,
        _EMERGENCY_ACTION_INVALID = -EINVAL,
} EmergencyAction;

typedef enum EmergencyActionFlags {
        EMERGENCY_ACTION_IS_WATCHDOG = 1 << 0, /* this action triggered by a watchdog or other kind of timeout */
        EMERGENCY_ACTION_WARN        = 1 << 1, /* log at LOG_WARNING + write to system console */
        EMERGENCY_ACTION_SLEEP_5S    = 1 << 2, /* wait 5s before executing action; only honoured together with EMERGENCY_ACTION_WARN */
        _EMERGENCY_ACTION_FLAGS_MAX  = (1 << 3) - 1,
} EmergencyActionFlags;

void emergency_action(
                Manager *m,
                EmergencyAction action,
                EmergencyActionFlags flags,
                const char *reboot_arg,
                int exit_status,
                const char *reason);

const char* emergency_action_to_string(EmergencyAction i) _const_;
EmergencyAction emergency_action_from_string(const char *s) _pure_;

int parse_emergency_action(const char *value, RuntimeScope runtime_scope, EmergencyAction *ret);
