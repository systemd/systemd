/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

/*
 * Copyright © 2003 Greg Kroah-Hartman <greg@kroah.com>
 */

#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include "libudev.h"
#include "sd-device.h"
#include "sd-netlink.h"

#include "hashmap.h"
#include "label.h"
#include "libudev-private.h"
#include "macro.h"
#include "strv.h"
#include "util.h"

struct udev_event {
        struct udev_device *dev;
        struct udev_device *dev_parent;
        struct udev_device *dev_db;
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
};

typedef enum ResolveNamesTiming {
        RESOLVE_NAMES_NEVER,
        RESOLVE_NAMES_LATE,
        RESOLVE_NAMES_EARLY,
        _RESOLVE_NAMES_TIMING_MAX,
        _RESOLVE_NAMES_TIMING_INVALID = -1,
} ResolveNamesTiming;

/* udev-rules.c */
struct udev_rules;
struct udev_rules *udev_rules_new(ResolveNamesTiming resolve_names_timing);
struct udev_rules *udev_rules_unref(struct udev_rules *rules);
bool udev_rules_check_timestamp(struct udev_rules *rules);
int udev_rules_apply_to_event(struct udev_rules *rules, struct udev_event *event,
                              usec_t timeout_usec, usec_t timeout_warn_usec,
                              Hashmap *properties_list);
int udev_rules_apply_static_dev_perms(struct udev_rules *rules);

ResolveNamesTiming resolve_names_timing_from_string(const char *s) _pure_;
const char *resolve_names_timing_to_string(ResolveNamesTiming i) _const_;

/* udev-event.c */
struct udev_event *udev_event_new(struct udev_device *dev);
struct udev_event *udev_event_free(struct udev_event *event);
ssize_t udev_event_apply_format(struct udev_event *event,
                                const char *src, char *dest, size_t size,
                                bool replace_whitespace);
int udev_event_spawn(struct udev_event *event,
                     usec_t timeout_usec,
                     usec_t timeout_warn_usec,
                     bool accept_failure,
                     const char *cmd, char *result, size_t ressize);
int udev_event_execute_rules(struct udev_event *event,
                             usec_t timeout_usec, usec_t timeout_warn_usec,
                             Hashmap *properties_list,
                             struct udev_rules *rules);
void udev_event_execute_run(struct udev_event *event, usec_t timeout_usec, usec_t timeout_warn_usec);

/* Cleanup functions */
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_event*, udev_event_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_rules*, udev_rules_unref);
