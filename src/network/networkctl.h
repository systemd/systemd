/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-bus.h"

#include "output-mode.h"
#include "pager.h"

extern PagerFlags arg_pager_flags;
extern bool arg_legend;
extern bool arg_no_reload;
extern bool arg_all;
extern bool arg_stats;
extern bool arg_full;
extern bool arg_runtime;
extern unsigned arg_lines;
extern char *arg_drop_in;
extern JsonFormatFlags arg_json_format_flags;

bool networkd_is_running(void);
int acquire_bus(sd_bus **ret);
