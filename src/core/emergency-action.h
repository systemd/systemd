/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef enum EmergencyAction {
        EMERGENCY_ACTION_NONE,
        EMERGENCY_ACTION_REBOOT,
        EMERGENCY_ACTION_REBOOT_FORCE,
        EMERGENCY_ACTION_REBOOT_IMMEDIATE,
        EMERGENCY_ACTION_POWEROFF,
        EMERGENCY_ACTION_POWEROFF_FORCE,
        EMERGENCY_ACTION_POWEROFF_IMMEDIATE,
        _EMERGENCY_ACTION_MAX,
        _EMERGENCY_ACTION_INVALID = -1
} EmergencyAction;

#include "macro.h"
#include "manager.h"

int emergency_action(Manager *m, EmergencyAction action, const char *reboot_arg, const char *reason);

const char* emergency_action_to_string(EmergencyAction i) _const_;
EmergencyAction emergency_action_from_string(const char *s) _pure_;
