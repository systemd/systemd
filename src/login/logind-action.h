/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"

typedef enum HandleAction {
        HANDLE_IGNORE,

        HANDLE_POWEROFF,
        _HANDLE_ACTION_SHUTDOWN_FIRST = HANDLE_POWEROFF,
        HANDLE_REBOOT,
        HANDLE_HALT,
        HANDLE_KEXEC,
        HANDLE_SOFT_REBOOT,
        _HANDLE_ACTION_SHUTDOWN_LAST = HANDLE_SOFT_REBOOT,

        HANDLE_SUSPEND,
        _HANDLE_ACTION_SLEEP_FIRST = HANDLE_SUSPEND,
        HANDLE_HIBERNATE,
        HANDLE_HYBRID_SLEEP,
        HANDLE_SUSPEND_THEN_HIBERNATE,
        HANDLE_SLEEP, /* A "high-level" action that automatically choose an appropriate low-level sleep action */
        _HANDLE_ACTION_SLEEP_LAST = HANDLE_SLEEP,

        HANDLE_SECURE_ATTENTION_KEY,
        HANDLE_LOCK,
        HANDLE_FACTORY_RESET,

        _HANDLE_ACTION_MAX,
        _HANDLE_ACTION_INVALID = -EINVAL,
} HandleAction;

typedef struct HandleActionData HandleActionData;

typedef enum HandleActionSleepMask {
        HANDLE_SLEEP_SUSPEND_MASK                = 1U << HANDLE_SUSPEND,
        HANDLE_SLEEP_HIBERNATE_MASK              = 1U << HANDLE_HIBERNATE,
        HANDLE_SLEEP_HYBRID_SLEEP_MASK           = 1U << HANDLE_HYBRID_SLEEP,
        HANDLE_SLEEP_SUSPEND_THEN_HIBERNATE_MASK = 1U << HANDLE_SUSPEND_THEN_HIBERNATE,
} HandleActionSleepMask;

#define HANDLE_ACTION_SLEEP_MASK_DEFAULT (HANDLE_SLEEP_SUSPEND_THEN_HIBERNATE_MASK|HANDLE_SLEEP_SUSPEND_MASK|HANDLE_SLEEP_HIBERNATE_MASK)

#include "logind-inhibit.h"
#include "logind.h"
#include "sleep-config.h"

static inline bool handle_action_valid(HandleAction a) {
        return a >= 0 && a < _HANDLE_ACTION_MAX;
}

static inline bool HANDLE_ACTION_IS_SHUTDOWN(HandleAction a) {
        return a >= _HANDLE_ACTION_SHUTDOWN_FIRST && a <= _HANDLE_ACTION_SHUTDOWN_LAST;
}

static inline bool HANDLE_ACTION_IS_SLEEP(HandleAction a) {
        return a >= _HANDLE_ACTION_SLEEP_FIRST && a <= _HANDLE_ACTION_SLEEP_LAST;
}

struct HandleActionData {
        HandleAction handle;
        const char *target;
        InhibitWhat inhibit_what;
        const char *polkit_action;
        const char *polkit_action_multiple_sessions;
        const char *polkit_action_ignore_inhibit;
        SleepOperation sleep_operation;
        const char* message_id;
        const char* message;
        const char* log_verb;
};

int handle_action_get_enabled_sleep_actions(HandleActionSleepMask mask, char ***ret);
HandleAction handle_action_sleep_select(Manager *m);

int manager_handle_action(
                Manager *m,
                InhibitWhat inhibit_key,
                HandleAction handle,
                bool ignore_inhibited,
                bool is_edge,
                const char *action_seat);

const char* handle_action_verb_to_string(HandleAction h) _const_;

const char* handle_action_to_string(HandleAction h) _const_;
HandleAction handle_action_from_string(const char *s) _pure_;

const HandleActionData* handle_action_lookup(HandleAction handle);

CONFIG_PARSER_PROTOTYPE(config_parse_handle_action);

CONFIG_PARSER_PROTOTYPE(config_parse_handle_action_sleep);
