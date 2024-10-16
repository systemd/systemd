/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "hashmap.h"

int header_put(OrderedHashmap **headers, char *name, char *value);

CONFIG_PARSER_PROTOTYPE(config_parse_header);
