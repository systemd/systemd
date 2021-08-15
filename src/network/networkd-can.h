/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/can/netlink.h>

#include "sd-netlink.h"

#include "conf-parser.h"

typedef struct Link Link;

int can_set_netlink_message(Link *link, sd_netlink_message *m);

CONFIG_PARSER_PROTOTYPE(config_parse_can_bitrate);
CONFIG_PARSER_PROTOTYPE(config_parse_can_time_quanta);
CONFIG_PARSER_PROTOTYPE(config_parse_can_restart_usec);
CONFIG_PARSER_PROTOTYPE(config_parse_can_control_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_can_termination);
