/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"

typedef struct Link Link;

int link_configure_can(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_can_bitrate);
