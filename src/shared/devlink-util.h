/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <linux/devlink.h>

#include "macro.h"

const char *devlink_cmd_to_string(int cmd) _const_;

typedef enum DevlinkDevESwitchMode {
        _DEVLINK_DEV_ESWITCH_MODE_LEGACY    = DEVLINK_ESWITCH_MODE_LEGACY,
        _DEVLINK_DEV_ESWITCH_MODE_SWITCHDEV = DEVLINK_ESWITCH_MODE_SWITCHDEV,
        _DEVLINK_DEV_ESWITCH_MODE_MAX,
        _DEVLINK_DEV_ESWITCH_MODE_INVALID   = -EINVAL,
} DevlinkDevESwitchMode;

const char *devlink_dev_eswitch_mode_to_string(DevlinkDevESwitchMode d) _const_;
DevlinkDevESwitchMode devlink_dev_eswitch_mode_from_string(const char *d) _pure_;
