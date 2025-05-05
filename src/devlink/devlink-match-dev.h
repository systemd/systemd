/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser-forward.h"

typedef struct DevlinkMatchDev {
        char *bus_name; /* first part of the handle */
        char *dev_name; /* second part of the handle */
} DevlinkMatchDev;

CONFIG_PARSER_PROTOTYPE(config_parse_devlink_dev_handle);
