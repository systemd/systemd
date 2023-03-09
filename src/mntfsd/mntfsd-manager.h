/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "sd-event.h"

typedef struct Manager Manager;

#include "hashmap.h"
#include "ratelimit.h"

#define MNTFS_WORKERS_MIN 3
#define MNTFS_WORKERS_MAX 4096

struct Manager {
        sd_event *event;

        Set *workers_fixed;    /* Workers 0…MNTFS_WORKERS_MIN */
        Set *workers_dynamic;  /* Workers MNTFS_WORKERS_MIN+1…MNTFS_WORKERS_MAX */

        int listen_fd;

        RateLimit worker_ratelimit;
};

int manager_new(Manager **ret);
Manager* manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_startup(Manager *m);
