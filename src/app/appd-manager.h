/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-future.h"

#include "appd-forward.h"

typedef struct Manager {
        sd_event *event;

        Hashmap *instances; /* cg_path -> App */
        sd_varlink_server *varlink_instance_server;
        sd_future *varlink_instance_notifier;
        sd_channel *varlink_instance_notifications;
} Manager;
