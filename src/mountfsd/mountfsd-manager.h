/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "ratelimit.h"

#define MOUNTFS_WORKERS_MIN 3
#define MOUNTFS_WORKERS_MAX 4096

typedef struct Manager {
        sd_event *event;

        Set *workers_fixed;    /* Workers 0…MOUNTFS_WORKERS_MIN */
        Set *workers_dynamic;  /* Workers MOUNTFS_WORKERS_MIN+1…MOUNTFS_WORKERS_MAX */

        int listen_fd;

        RateLimit worker_ratelimit;
} Manager;

int manager_new(Manager **ret);
Manager* manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_startup(Manager *m);
