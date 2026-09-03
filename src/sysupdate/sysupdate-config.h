/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

#include "conf-parser-forward.h"
#include "forward.h"

CONFIG_PARSER_PROTOTYPE(config_parse_url_specifiers);
CONFIG_PARSER_PROTOTYPE(config_parse_url_specifiers_many);
CONFIG_PARSER_PROTOTYPE(config_parse_condition);
CONFIG_PARSER_PROTOTYPE(config_parse_protect_version);
CONFIG_PARSER_PROTOTYPE(config_parse_version_bound);

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(suggest_on_type, ConditionType);

/* JSON dispatchers for fields mirroring the settings above, used when definitions are acquired in JSON form */
int json_dispatch_versions(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
