/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "appd-forward.h"

typedef struct Manager {
        sd_event *event;

        Hashmap *instances; /* cg_path -> App */

        sd_varlink_server *varlink_instance_server;
} Manager;
