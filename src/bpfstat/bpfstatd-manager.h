/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-event.h"

#include "varlink.h"

/* Polling interval for BPF timer  */
#define BPF_TIMER_INTERVAL_USEC USEC_PER_MINUTE /* 1 minute */
#define BPFSTATD_VARLINK_ADDRESS "/run/systemd/bpf/io.systemd.BpfStat"

typedef struct Manager {
        sd_event *event;
        sd_event_source *bpf_timer_event_source;

        bool enable_logging;

        VarlinkServer *varlink_server;
} Manager;

int manager_new(Manager **ret);
Manager* manager_free(Manager *m);
int manager_start(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);
