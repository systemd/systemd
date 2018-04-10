/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek
***/

#include "udev.h"
#include "util.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev*, udev_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_device*, udev_device_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_enumerate*, udev_enumerate_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_event*, udev_event_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_rules*, udev_rules_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_ctrl*, udev_ctrl_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_ctrl_connection*, udev_ctrl_connection_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_ctrl_msg*, udev_ctrl_msg_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_monitor*, udev_monitor_unref);

#define _cleanup_udev_unref_ _cleanup_(udev_unrefp)
#define _cleanup_udev_device_unref_ _cleanup_(udev_device_unrefp)
#define _cleanup_udev_enumerate_unref_ _cleanup_(udev_enumerate_unrefp)
#define _cleanup_udev_event_unref_ _cleanup_(udev_event_unrefp)
#define _cleanup_udev_rules_unref_ _cleanup_(udev_rules_unrefp)
#define _cleanup_udev_ctrl_unref_ _cleanup_(udev_ctrl_unrefp)
#define _cleanup_udev_ctrl_connection_unref_ _cleanup_(udev_ctrl_connection_unrefp)
#define _cleanup_udev_ctrl_msg_unref_ _cleanup_(udev_ctrl_msg_unrefp)
#define _cleanup_udev_monitor_unref_ _cleanup_(udev_monitor_unrefp)
#define _cleanup_udev_list_cleanup_ _cleanup_(udev_list_cleanup)

int udev_parse_config(void);
