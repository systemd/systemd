/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "user-record.h"
#include "group-record.h"
#include "nspawn-mount.h"

typedef struct BindUserData {
        /* The host's user/group records */
        UserRecord *host_user;
        GroupRecord *host_group;

        /* The mapped records to place into the container */
        UserRecord *payload_user;
        GroupRecord *payload_group;
} BindUserData;

typedef struct BindUserContext {
        BindUserData *data;
        size_t n_data;
} BindUserContext;

BindUserContext* bind_user_context_free(BindUserContext *c);

DEFINE_TRIVIAL_CLEANUP_FUNC(BindUserContext*, bind_user_context_free);

int bind_user_prepare(const char *directory, char **bind_user, uid_t uid_shift, uid_t uid_range, CustomMount **custom_mounts, size_t *n_custom_mounts, BindUserContext **ret);

int bind_user_setup(const BindUserContext *c, const char *root);
