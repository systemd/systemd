/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "homed-forward.h"

int manager_parse_config_file(Manager *m);

const struct ConfigPerfItem* homed_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

CONFIG_PARSER_PROTOTYPE(config_parse_default_storage);
CONFIG_PARSER_PROTOTYPE(config_parse_default_file_system_type);
