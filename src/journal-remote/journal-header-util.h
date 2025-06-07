/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser-forward.h"
#include "forward.h"

bool header_value_is_valid(const char *value);

bool header_name_is_valid(const char *value);

int header_put(OrderedHashmap **headers, const char *name, const char *value);

CONFIG_PARSER_PROTOTYPE(config_parse_header);
