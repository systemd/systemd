/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "sd-event.h"

typedef struct Manager Manager;

#include "hashmap.h"
#include "ratelimit.h"

#define USERDB_WORKERS_MIN 3
#define USERDB_WORKERS_MAX 4096

struct Manager {
        sd_event *event;

        Set *workers_fixed;    /* Workers 0…USERDB_WORKERS_MIN */
        Set *workers_dynamic;  /* Workers USERD_WORKERS_MIN+1…USERDB_WORKERS_MAX */

        int listen_fd;

        RateLimit worker_ratelimit;

        sd_event_source *deferred_start_worker_event_source;

        struct userns_restrict_bpf *userns_restrict_bpf;
        struct ring_buffer *userns_restrict_bpf_ring_buffer;
        sd_event_source *userns_restrict_bpf_ring_buffer_event_source;

        int registry_fd;
};

int manager_new(Manager **ret);
Manager* manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_startup(Manager *m);
