/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2014 Vinay Kulkarni <kulkarniv@vmware.com>
***/

#include "conf-parser.h"

typedef struct Manager Manager;

int manager_parse_config_file(Manager *m);

const struct ConfigPerfItem* networkd_gperf_lookup(const char *key, GPERF_LEN_TYPE length);
