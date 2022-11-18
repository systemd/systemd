/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "sd-event.h"

#include "macro.h"
#include "time-util.h"
#include "varlink.h"

typedef struct UdevCtrl UdevCtrl;

typedef enum UdevCtrlMessageType {
        _UDEV_CTRL_END_MESSAGES,
        UDEV_CTRL_RELOAD,
        UDEV_CTRL_SET_ENV,
        UDEV_CTRL_SET_CHILDREN_MAX,
        UDEV_CTRL_EXIT,
} UdevCtrlMessageType;

typedef union UdevCtrlMessageValue {
        int intval;
        char buf[256];
} UdevCtrlMessageValue;

typedef int (*udev_ctrl_handler_t)(UdevCtrl *udev_ctrl, UdevCtrlMessageType type,
                                   const UdevCtrlMessageValue *value, void *userdata);

int udev_ctrl_new_from_fd(UdevCtrl **ret, int fd);
int udev_ctrl_new_with_link(UdevCtrl **ret, Varlink *link);

int udev_ctrl_enable_receiving(UdevCtrl *uctrl);
UdevCtrl *udev_ctrl_ref(UdevCtrl *uctrl);
UdevCtrl *udev_ctrl_unref(UdevCtrl *uctrl);
int udev_ctrl_attach_event(UdevCtrl *uctrl, sd_event *event);
int udev_ctrl_start(UdevCtrl *uctrl, udev_ctrl_handler_t callback, void *userdata);
sd_event_source *udev_ctrl_get_event_source(UdevCtrl *uctrl);

int udev_ctrl_wait(UdevCtrl *uctrl, usec_t timeout);

int udev_ctrl_send(UdevCtrl *uctrl, UdevCtrlMessageType type, const void *data);

static inline int udev_ctrl_send_reload(UdevCtrl *uctrl) {
        return udev_ctrl_send(uctrl, UDEV_CTRL_RELOAD, NULL);
}

static inline int udev_ctrl_send_set_env(UdevCtrl *uctrl, const char *key) {
        return udev_ctrl_send(uctrl, UDEV_CTRL_SET_ENV, key);
}

static inline int udev_ctrl_send_set_children_max(UdevCtrl *uctrl, int count) {
        return udev_ctrl_send(uctrl, UDEV_CTRL_SET_CHILDREN_MAX, INT_TO_PTR(count));
}

int udev_ctrl_send_ping(UdevCtrl *uctrl);

static inline int udev_ctrl_send_exit(UdevCtrl *uctrl) {
        return udev_ctrl_send(uctrl, UDEV_CTRL_EXIT, NULL);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(UdevCtrl*, udev_ctrl_unref);
