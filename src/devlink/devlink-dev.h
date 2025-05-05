/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser-forward.h"
#include "devlink-util.h"

#include "devlink.h"

typedef struct DevlinkDev {
        Devlink meta;
        DevlinkDevESwitchMode eswitch_mode;
} DevlinkDev;

DEFINE_DEVLINK_CAST(DEV, DevlinkDev);

extern const DevlinkVTable devlink_dev_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_devlink_dev_eswitch_mode);
