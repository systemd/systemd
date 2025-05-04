/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser-forward.h"

typedef struct DevlinkMatchPort {
        bool split;
        bool split_explicit;
} DevlinkMatchPort;

CONFIG_PARSER_PROTOTYPE(config_parse_devlink_port_split);
