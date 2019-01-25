/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include "sd-event.h"

#include "macro.h"
#include "time-util.h"

struct udev_ctrl;

enum udev_ctrl_msg_type {
        UDEV_CTRL_UNKNOWN,
        UDEV_CTRL_SET_LOG_LEVEL,
        UDEV_CTRL_STOP_EXEC_QUEUE,
        UDEV_CTRL_START_EXEC_QUEUE,
        UDEV_CTRL_RELOAD,
        UDEV_CTRL_SET_ENV,
        UDEV_CTRL_SET_CHILDREN_MAX,
        UDEV_CTRL_PING,
        UDEV_CTRL_EXIT,
};

union udev_ctrl_msg_value {
        int intval;
        char buf[256];
};

typedef int (*udev_ctrl_handler_t)(struct udev_ctrl *udev_ctrl, enum udev_ctrl_msg_type type,
                                   const union udev_ctrl_msg_value *value, void *userdata);

int udev_ctrl_new_from_fd(struct udev_ctrl **ret, int fd);
static inline int udev_ctrl_new(struct udev_ctrl **ret) {
        return udev_ctrl_new_from_fd(ret, -1);
}

int udev_ctrl_enable_receiving(struct udev_ctrl *uctrl);
struct udev_ctrl *udev_ctrl_ref(struct udev_ctrl *uctrl);
struct udev_ctrl *udev_ctrl_unref(struct udev_ctrl *uctrl);
int udev_ctrl_cleanup(struct udev_ctrl *uctrl);
int udev_ctrl_attach_event(struct udev_ctrl *uctrl, sd_event *event);
int udev_ctrl_start(struct udev_ctrl *uctrl, udev_ctrl_handler_t callback, void *userdata);
sd_event_source *udev_ctrl_get_event_source(struct udev_ctrl *uctrl);

int udev_ctrl_send_set_log_level(struct udev_ctrl *uctrl, int priority, usec_t timeout);
int udev_ctrl_send_stop_exec_queue(struct udev_ctrl *uctrl, usec_t timeout);
int udev_ctrl_send_start_exec_queue(struct udev_ctrl *uctrl, usec_t timeout);
int udev_ctrl_send_reload(struct udev_ctrl *uctrl, usec_t timeout);
int udev_ctrl_send_ping(struct udev_ctrl *uctrl, usec_t timeout);
int udev_ctrl_send_exit(struct udev_ctrl *uctrl, usec_t timeout);
int udev_ctrl_send_set_env(struct udev_ctrl *uctrl, const char *key, usec_t timeout);
int udev_ctrl_send_set_children_max(struct udev_ctrl *uctrl, int count, usec_t timeout);

DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_ctrl*, udev_ctrl_unref);
