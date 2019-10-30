/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "time-util.h"

int tc_time_to_tick(usec_t t, uint32_t *ret);
int parse_tc_percent(const char *s, uint32_t *percent);
