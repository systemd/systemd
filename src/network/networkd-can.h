/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

#include "conf-parser.h"

typedef struct Link Link;

int can_set_netlink_message(Link *link, sd_netlink_message *m);

CONFIG_PARSER_PROTOTYPE(config_parse_can_bitrate);
CONFIG_PARSER_PROTOTYPE(config_parse_can_restart_usec);
