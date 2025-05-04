/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "devlink-util.h"
#include "string-table.h"

static const char * const devlink_cmd_table[__DEVLINK_CMD_MAX] = {
        [DEVLINK_CMD_NEW] = "new",
        [DEVLINK_CMD_DEL] = "del",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(devlink_cmd, int);

static const char* const devlink_dev_eswitch_mode_table[_DEVLINK_DEV_ESWITCH_MODE_MAX] = {
        [_DEVLINK_DEV_ESWITCH_MODE_LEGACY] = "legacy",
        [_DEVLINK_DEV_ESWITCH_MODE_SWITCHDEV] = "switchdev",
};

DEFINE_STRING_TABLE_LOOKUP(devlink_dev_eswitch_mode, DevlinkDevESwitchMode);
