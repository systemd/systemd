/* SPDX-License-Identifier: GPL-2.0-or-later */
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
#define UDEV_ALLOWED_CHARS_INPUT        "/ $%?,"

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

size_t udev_event_apply_format(
                UdevEvent *event,
                const char *src,
                char *dest,
                size_t size,
                bool replace_whitespace,
                bool *ret_truncated);
int udev_check_format(const char *value, size_t *offset, const char **hint);
int udev_event_spawn(
                UdevEvent *event,
                usec_t timeout_usec,
                int timeout_signal,
                bool accept_failure,
                const char *cmd,
                char *result,
                size_t ressize,
                bool *ret_truncated);
int udev_event_execute_rules(
                UdevEvent *event,
                int inotify_fd,
                usec_t timeout_usec,
                int timeout_signal,
                Hashmap *properties_list,
                UdevRules *rules);
void udev_event_execute_run(UdevEvent *event, usec_t timeout_usec, int timeout_signal);
void udev_event_process_inotify_watch(UdevEvent *event, int inotify_fd);

static inline usec_t udev_warn_timeout(usec_t timeout_usec) {
        return DIV_ROUND_UP(timeout_usec, 3);
}
