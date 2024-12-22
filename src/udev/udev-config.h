/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>

#include "time-util.h"
#include "udev-def.h"

extern bool arg_daemonize;

typedef struct Manager Manager;

typedef struct UdevConfig {
        int log_level;
        ResolveNameTiming resolve_name_timing;
        unsigned children_max;
        usec_t exec_delay_usec;
        usec_t timeout_usec;
        int timeout_signal;
        bool blockdev_read_only;
} UdevConfig;

#define UDEV_CONFIG_INIT                                             \
        (UdevConfig) {                                               \
                .log_level = -1,                                     \
                .resolve_name_timing = _RESOLVE_NAME_TIMING_INVALID, \
        }

int manager_load(Manager *manager, int argc, char *argv[]);
UdevReloadFlags manager_reload_config(Manager *manager);
void udev_config_set_default_children_max(UdevConfig *c);
