/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "hashmap.h"
#include "sd-bus.h"
#include "sd-event.h"

#include "macro.h"

/* Polling interval for BPF timer  */
#define BPF_TIMER_INTERVAL_USEC 5 * USEC_PER_SEC /* 5.0 seconds */

typedef struct Manager Manager;

struct Manager {
        sd_event *event;

        sd_event_source *bpf_timer_event_source;
};

int manager_new(Manager **ret);
Manager* manager_free(Manager *m);
int manager_start(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);
