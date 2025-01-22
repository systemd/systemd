/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

/*
 * Copyright © 2003 Greg Kroah-Hartman <greg@kroah.com>
 */

#include <stdbool.h>
#include <stddef.h>

#include "sd-device.h"
#include "sd-netlink.h"

#include "hashmap.h"
#include "macro.h"
#include "time-util.h"
#include "udev-def.h"
#include "user-util.h"

typedef struct UdevRules UdevRules;
typedef struct UdevWorker UdevWorker;

typedef struct UdevEvent {
        unsigned n_ref;

        UdevWorker *worker;
        sd_netlink *rtnl;
        sd_device *dev;
        sd_device *dev_parent;
        sd_device *dev_db_clone;
        char *name;
        char **altnames;
        char *program_result;
        mode_t mode;
        uid_t uid;
        gid_t gid;
        OrderedHashmap *seclabel_list;
        OrderedHashmap *run_list;
        Hashmap *written_sysattrs;
        Hashmap *written_sysctls;
        usec_t birth_usec;
        unsigned builtin_run;
        unsigned builtin_ret;
        UdevRuleEscapeType esc:8;
        bool inotify_watch;
        bool inotify_watch_final;
        bool group_final;
        bool owner_final;
        bool mode_final;
        bool name_final;
        bool devlink_final;
        bool run_final;
        bool trace;
        bool log_level_was_debug;
        int default_log_level;
        EventMode event_mode;
} UdevEvent;

UdevEvent* udev_event_new(sd_device *dev, UdevWorker *worker, EventMode mode);
UdevEvent* udev_event_ref(UdevEvent *event);
UdevEvent* udev_event_unref(UdevEvent *event);
DEFINE_TRIVIAL_CLEANUP_FUNC(UdevEvent*, udev_event_unref);

int udev_event_execute_rules(UdevEvent *event, UdevRules *rules);

static inline bool EVENT_MODE_DESTRUCTIVE(UdevEvent *event) {
        assert(event);
        return IN_SET(event->event_mode, EVENT_UDEV_WORKER, EVENT_TEST_RULE_RUNNER);
}
