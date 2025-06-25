/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "udev-def.h"
#include "udev-forward.h"

extern bool arg_daemonize;

typedef struct UdevConfig {
        int log_level;
        ResolveNameTiming resolve_name_timing;
        unsigned children_max;
        usec_t exec_delay_usec;
        usec_t timeout_usec;
        int timeout_signal;
        bool blockdev_read_only;
        bool trace;
} UdevConfig;

#define UDEV_CONFIG_INIT                                             \
        (UdevConfig) {                                               \
                .log_level = -1,                                     \
                .resolve_name_timing = _RESOLVE_NAME_TIMING_INVALID, \
        }

void manager_set_children_max(Manager *manager, unsigned n);
void manager_set_log_level(Manager *manager, int log_level);
void manager_set_trace(Manager *manager, bool enable);
void manager_set_environment(Manager *manager, char * const *v);

int manager_load(Manager *manager, int argc, char *argv[]);
UdevReloadFlags manager_reload_config(Manager *manager);
UdevReloadFlags manager_revert_config(Manager *manager);

int manager_serialize_config(Manager *manager);
int manager_deserialize_config(Manager *manager, int *fd);

usec_t manager_kill_worker_timeout(Manager *manager);
