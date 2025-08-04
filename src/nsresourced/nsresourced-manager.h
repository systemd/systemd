/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "ratelimit.h"

#define NSRESOURCE_WORKERS_MIN 5
#define NSRESOURCE_WORKERS_MAX 4096

typedef struct Manager {
        sd_event *event;

        Set *workers_fixed;    /* Workers 0…NSRESOURCE_WORKERS_MIN */
        Set *workers_dynamic;  /* Workers NSRESOURCES_WORKERS_MIN+1…NSRESOURCES_WORKERS_MAX */

        int listen_fd;

        RateLimit worker_ratelimit;

        sd_event_source *deferred_start_worker_event_source;

#if HAVE_VMLINUX_H
        struct userns_restrict_bpf *userns_restrict_bpf;
        struct ring_buffer *userns_restrict_bpf_ring_buffer;
        sd_event_source *userns_restrict_bpf_ring_buffer_event_source;
#endif

        int registry_fd;
} Manager;

int manager_new(Manager **ret);
Manager* manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_startup(Manager *m);
