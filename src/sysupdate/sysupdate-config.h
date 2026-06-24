/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser-forward.h"
#include "shared-forward.h"
#include "specifier.h"

CONFIG_PARSER_PROTOTYPE(config_parse_url_specifiers);
CONFIG_PARSER_PROTOTYPE(config_parse_url_specifiers_many);

extern const Specifier specifier_table[];

CONFIG_PARSER_PROTOTYPE(config_parse_condition);

DECLARE_STRING_TABLE_LOOKUP(suggest_on_type, ConditionType);
