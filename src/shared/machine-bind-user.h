/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct MachineBindUserData {
        /* The host's user/group records */
        UserRecord *host_user;
        GroupRecord *host_group;

        /* The mapped records to place into the container */
        UserRecord *payload_user;
        GroupRecord *payload_group;
} MachineBindUserData;

typedef struct MachineBindUserContext {
        MachineBindUserData *data;
        size_t n_data;
} MachineBindUserContext;

MachineBindUserContext* machine_bind_user_context_free(MachineBindUserContext *c);

DEFINE_TRIVIAL_CLEANUP_FUNC(MachineBindUserContext*, machine_bind_user_context_free);

int machine_bind_user_prepare(
                const char *directory,
                char **bind_user,
                const char *bind_user_shell,
                bool bind_user_shell_copy,
                MachineBindUserContext **ret);
