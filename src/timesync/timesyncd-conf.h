/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "timesyncd-manager.h"

const struct ConfigPerfItem* timesyncd_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

int manager_parse_server_string(Manager *m, ServerType type, const char *string);

CONFIG_PARSER_PROTOTYPE(config_parse_servers);

int manager_parse_config_file(Manager *m);
int manager_parse_fallback_string(Manager *m, const char *string);
