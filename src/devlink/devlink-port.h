/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser-forward.h"

#include "devlink.h"

typedef struct DevlinkPort {
        Devlink meta;
        uint32_t split_count;
} DevlinkPort;

#define _DEVLINK_PORT_SPLIT_COUNT_INVALID UINT32_MAX

DEFINE_DEVLINK_CAST(PORT, DevlinkPort);

CONFIG_PARSER_PROTOTYPE(config_parse_devlink_port_split_count);

extern const DevlinkVTable devlink_port_vtable;
