/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "sd-event.h"

#include "macro.h"
#include "time-util.h"

typedef struct UdevCtrl UdevCtrl;

int udev_ctrl_new_from_fd(UdevCtrl **ret, int fd);

int udev_ctrl_enable_receiving(UdevCtrl *uctrl);
UdevCtrl *udev_ctrl_ref(UdevCtrl *uctrl);
UdevCtrl *udev_ctrl_unref(UdevCtrl *uctrl);
int udev_ctrl_attach_event(UdevCtrl *uctrl, sd_event *event);
sd_event_source *udev_ctrl_get_event_source(UdevCtrl *uctrl);

DEFINE_TRIVIAL_CLEANUP_FUNC(UdevCtrl*, udev_ctrl_unref);
