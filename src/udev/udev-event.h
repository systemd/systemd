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
#include "udev-rules.h"
#include "user-util.h"

typedef struct UdevEvent {
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
        usec_t exec_delay_usec;
        usec_t birth_usec;
        sd_netlink *rtnl;
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
        bool log_level_was_debug;
        int default_log_level;
} UdevEvent;

UdevEvent *udev_event_new(sd_device *dev, usec_t exec_delay_usec, sd_netlink *rtnl, int log_level);
UdevEvent *udev_event_free(UdevEvent *event);
DEFINE_TRIVIAL_CLEANUP_FUNC(UdevEvent*, udev_event_free);

int udev_event_execute_rules(
                UdevEvent *event,
                usec_t timeout_usec,
                int timeout_signal,
                Hashmap *properties_list,
                UdevRules *rules);
