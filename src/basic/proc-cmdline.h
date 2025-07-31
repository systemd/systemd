/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum ProcCmdlineFlags {
        PROC_CMDLINE_STRIP_RD_PREFIX    = 1 << 0, /* automatically strip "rd." prefix if it is set (and we are in the initrd, since otherwise we'd not consider it anyway) */
        PROC_CMDLINE_VALUE_OPTIONAL     = 1 << 1, /* the value is optional (for boolean switches that can omit the value) */
        PROC_CMDLINE_RD_STRICT          = 1 << 2, /* ignore this in the initrd */
        PROC_CMDLINE_TRUE_WHEN_MISSING  = 1 << 3, /* default to true when the key is missing for bool */
} ProcCmdlineFlags;

typedef int (*proc_cmdline_parse_t)(const char *key, const char *value, void *data);

int proc_cmdline_filter_pid1_args(char **argv, char ***ret);

int proc_cmdline(char **ret);
int proc_cmdline_strv(char ***ret);

int proc_cmdline_parse(const proc_cmdline_parse_t parse, void *userdata, ProcCmdlineFlags flags);

int proc_cmdline_get_key(const char *parameter, ProcCmdlineFlags flags, char **ret_value);
int proc_cmdline_get_bool(const char *key, ProcCmdlineFlags flags, bool *ret);

int proc_cmdline_get_key_many_internal(ProcCmdlineFlags flags, ...);
#define proc_cmdline_get_key_many(flags, ...) proc_cmdline_get_key_many_internal(flags, __VA_ARGS__, NULL)

char* proc_cmdline_key_startswith(const char *s, const char *prefix);
bool proc_cmdline_key_streq(const char *x, const char *y);

/* A little helper call, to be used in proc_cmdline_parse_t callbacks */
bool proc_cmdline_value_missing(const char *key, const char *value);
