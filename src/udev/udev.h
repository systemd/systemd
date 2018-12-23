/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

/*
 * Copyright © 2003 Greg Kroah-Hartman <greg@kroah.com>
 */

#include "sd-device.h"
#include "sd-netlink.h"

#include "hashmap.h"
#include "macro.h"
#include "udev-util.h"
#include "util.h"

#define READ_END 0
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
        Hashmap *seclabel_list;
        Hashmap *run_list;
        usec_t exec_delay_usec;
        usec_t birth_usec;
        sd_netlink *rtnl;
        unsigned builtin_run;
        unsigned builtin_ret;
        bool inotify_watch;
        bool inotify_watch_final;
        bool group_set;
        bool group_final;
        bool owner_set;
        bool owner_final;
        bool mode_set;
        bool mode_final;
        bool name_final;
        bool devlink_final;
        bool run_final;
} UdevEvent;

/* udev-rules.c */
typedef struct UdevRules UdevRules;

int udev_rules_new(UdevRules **ret_rules, ResolveNameTiming resolve_name_timing);
UdevRules *udev_rules_free(UdevRules *rules);

bool udev_rules_check_timestamp(UdevRules *rules);
int udev_rules_apply_to_event(UdevRules *rules, UdevEvent *event, usec_t timeout_usec, Hashmap *properties_list);
int udev_rules_apply_static_dev_perms(UdevRules *rules);

static inline usec_t udev_warn_timeout(usec_t timeout_usec) {
        return DIV_ROUND_UP(timeout_usec, 3);
}

/* udev-event.c */
UdevEvent *udev_event_new(sd_device *dev, usec_t exec_delay_usec, sd_netlink *rtnl);
UdevEvent *udev_event_free(UdevEvent *event);
ssize_t udev_event_apply_format(UdevEvent *event, const char *src, char *dest, size_t size, bool replace_whitespace);
int udev_event_spawn(UdevEvent *event, usec_t timeout_usec, bool accept_failure, const char *cmd, char *result, size_t ressize);
int udev_event_execute_rules(UdevEvent *event, usec_t timeout_usec, Hashmap *properties_list, UdevRules *rules);
void udev_event_execute_run(UdevEvent *event, usec_t timeout_usec);

/* Cleanup functions */
DEFINE_TRIVIAL_CLEANUP_FUNC(UdevEvent *, udev_event_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(UdevRules *, udev_rules_free);
