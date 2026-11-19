/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "appd-forward.h"

typedef struct AppInstance {
        unsigned n_ref;
        Manager *manager;

        char *cg_path;
        int cg_fd;
        sd_event_source *cg_inotify;
        char *unit;

        uint64_t generation;
        bool published;
        bool ever_queried;

        char *app_id;
        char *collection;
        char *sandbox;

        sd_json_variant *permissions;
        sd_json_variant *entitlements;

        sd_future *last_notify;
} AppInstance;

DECLARE_TRIVIAL_REF_UNREF_FUNC(AppInstance, app_instance);
DEFINE_TRIVIAL_CLEANUP_FUNC(AppInstance*, app_instance_unref);

int app_instance_from_pidref(Manager *manager, const PidRef *process, AppInstance **ret);
int app_instance_from_path(Manager *manager, const char *path, AppInstance **ret);

int app_instance_commit(AppInstance *instance);

bool app_instance_same_app(AppInstance *a, AppInstance *b);

typedef enum AppInstanceEvent {
        APP_INSTANCE_APPEARED,
        APP_INSTANCE_CHANGED,
        APP_INSTANCE_DISAPPEARED,
        _APP_INSTANCE_EVENT_MAX,
        _APP_INSTANCE_EVENT_INVALID = -EINVAL,
} AppInstanceEvent;

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(app_instance_event, AppInstanceEvent);

int app_instance_notify(AppInstance *instance, AppInstanceEvent event);
void app_instance_notify_async(AppInstance *instance, AppInstanceEvent event);
