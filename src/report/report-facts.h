/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

#define FACT_PREFIX "io.systemd.Facts."

int local_facts_list(sd_json_variant ***ret, size_t *ret_n);
int local_facts_describe(sd_json_variant ***ret, size_t *ret_n);
