/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "appd-forward.h"

typedef struct AppInstance {
        unsigned n_ref;

        Manager *manager;
        bool ever_queried;

        char *cg_path;
        int cg_fd;

        uint64_t generation;

        char *app_id;
        char *collection;
        char *sandbox;

        sd_json_variant *permissions;
        sd_json_variant *entitlements;
} AppInstance;

DECLARE_TRIVIAL_REF_UNREF_FUNC(AppInstance, app_instance);
DEFINE_TRIVIAL_CLEANUP_FUNC(AppInstance*, app_instance_unref);

int app_instance_get(Manager *m, const PidRef *p, AppInstance **ret);

int app_instance_commit(AppInstance *instance);

bool app_instance_same_app(AppInstance *a, AppInstance *b);
