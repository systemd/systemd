/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

extern usec_t arg_since;
extern usec_t arg_until;
extern const char *arg_field;
extern const char *arg_debugger;
extern char **arg_debugger_args;
extern const char *arg_directory;
extern char **arg_file;
extern sd_json_format_flags_t arg_json_format_flags;
extern PagerFlags arg_pager_flags;
extern int arg_legend;
extern size_t arg_rows_max;
extern const char *arg_output;
extern bool arg_reverse;
extern bool arg_quiet;
extern bool arg_all;
extern char *arg_root;
