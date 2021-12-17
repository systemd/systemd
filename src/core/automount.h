/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Automount Automount;

#include "unit.h"

typedef enum AutomountResult {
        AUTOMOUNT_SUCCESS,
        AUTOMOUNT_FAILURE_RESOURCES,
        AUTOMOUNT_FAILURE_UNMOUNTED,
        AUTOMOUNT_FAILURE_START_LIMIT_HIT,
        AUTOMOUNT_FAILURE_MOUNT_START_LIMIT_HIT,
        _AUTOMOUNT_RESULT_MAX,
        _AUTOMOUNT_RESULT_INVALID = -EINVAL,
} AutomountResult;

struct Automount {
        Unit meta;

        AutomountState state, deserialized_state;

        char *where;
        char *extra_options;
        usec_t timeout_idle_usec;

        int pipe_fd;
        sd_event_source *pipe_event_source;
        mode_t directory_mode;
        dev_t dev_id;

        Set *tokens;
        Set *expire_tokens;

        sd_event_source *expire_event_source;

        AutomountResult result;
};

extern const UnitVTable automount_vtable;

const char* automount_result_to_string(AutomountResult i) _const_;
AutomountResult automount_result_from_string(const char *s) _pure_;

DEFINE_CAST(AUTOMOUNT, Automount);
