/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "bpfd-manager.h"

int manager_parse_config_file(Manager *m);

const struct ConfigPerfItem* bpfd_gperf_lookup(const char *key, GPERF_LEN_TYPE length);
