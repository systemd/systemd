/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "appd-forward.h"

int manager_instance_varlink_init(Manager *m);
void manager_instance_varlink_done(Manager *m);

typedef enum AppInstanceEvent {
        APP_INSTANCE_CHANGED,
        APP_INSTANCE_DISAPPEARED,
        _APP_INSTANCE_EVENT_MAX,
        _APP_INSTANCE_EVENT_INVALID = -EINVAL,
} AppInstanceEvent;

typedef int (*app_instance_notify_finished_t)(void *userdata);

int app_instance_notify(AppInstance *instance, AppInstanceEvent event, app_instance_notify_finished_t done, void *userdata);
