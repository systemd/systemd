/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "appd-forward.h"

typedef struct Manager {
        sd_event *event;

        Hashmap *instances; /* cg_path -> App */

        sd_varlink_server *varlink_instance_server;
} Manager;

int manager_new(Manager **ret);
int manager_startup(Manager *m);
Manager *manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);
