/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "output-mode.h"
#include "pager.h"

extern PagerFlags arg_pager_flags;
extern bool arg_legend;
extern bool arg_no_reload;
extern bool arg_all;
extern bool arg_stats;
extern bool arg_full;
extern bool arg_runtime;
extern bool arg_stdin;
extern unsigned arg_lines;
extern char *arg_drop_in;
extern sd_json_format_flags_t arg_json_format_flags;
extern bool arg_ask_password;
