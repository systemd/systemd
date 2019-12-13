/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

/*
 * Copyright © 2003 Greg Kroah-Hartman <greg@kroah.com>
 */

#include "sd-device.h"
#include "sd-netlink.h"

#include "hashmap.h"
#include "macro.h"
#include "udev-rules.h"
#include "udev-util.h"
#include "util.h"

#define READ_END  0
#define WRITE_END 1

typedef struct UdevEvent {
        sd_device *dev;
        sd_device *dev_parent;
        sd_device *dev_db_clone;
        char *name;
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
        bool inotify_watch:1;
        bool inotify_watch_final:1;
        bool group_final:1;
        bool owner_final:1;
        bool mode_final:1;
        bool name_final:1;
        bool devlink_final:1;
        bool run_final:1;
} UdevEvent;

UdevEvent *udev_event_new(sd_device *dev, usec_t exec_delay_usec, sd_netlink *rtnl);
UdevEvent *udev_event_free(UdevEvent *event);
DEFINE_TRIVIAL_CLEANUP_FUNC(UdevEvent*, udev_event_free);

ssize_t udev_event_apply_format(UdevEvent *event,
                                const char *src, char *dest, size_t size,
                                bool replace_whitespace);
int udev_check_format(const char *value, size_t *offset, const char **hint);
int udev_event_spawn(UdevEvent *event,
                     usec_t timeout_usec,
                     bool accept_failure,
                     const char *cmd, char *result, size_t ressize);
int udev_event_execute_rules(UdevEvent *event,
                             usec_t timeout_usec,
                             Hashmap *properties_list,
                             UdevRules *rules);
void udev_event_execute_run(UdevEvent *event, usec_t timeout_usec);

static inline usec_t udev_warn_timeout(usec_t timeout_usec) {
        return DIV_ROUND_UP(timeout_usec, 3);
}
