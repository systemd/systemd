/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser-forward.h"
#include "forward.h"

CONFIG_PARSER_PROTOTYPE(config_parse_url_specifiers);
CONFIG_PARSER_PROTOTYPE(config_parse_url_specifiers_many);
CONFIG_PARSER_PROTOTYPE(config_parse_source_url);
CONFIG_PARSER_PROTOTYPE(config_parse_condition);

bool sysupdate_source_url_is_valid(const char *url) _pure_;

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(suggest_on_type, ConditionType);
