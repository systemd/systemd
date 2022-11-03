/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "locale-util.h"
#include "time-util.h"

typedef struct LocaleContext {
        usec_t mtime;
        char *locale[_VARIABLE_LC_MAX];
} LocaleContext;

typedef enum LocaleLoadFlag {
        LOCALE_LOAD_PROC_CMDLINE = 1 << 0,
        LOCALE_LOAD_LOCALE_CONF  = 1 << 1,
        LOCALE_LOAD_ENVIRONMENT  = 1 << 2,
        LOCALE_LOAD_SIMPLIFY     = 1 << 3,
} LocaleLoadFlag;

void locale_context_clear(LocaleContext *c);
int locale_context_load(LocaleContext *c, LocaleLoadFlag flag);
int locale_context_build_env(const LocaleContext *c, char ***ret_set, char ***ret_unset);
int locale_context_save(LocaleContext *c, char ***ret_set, char ***ret_unset);

int locale_context_merge(const LocaleContext *c, char *l[_VARIABLE_LC_MAX]);
void locale_context_take(LocaleContext *c, char *l[_VARIABLE_LC_MAX]);
bool locale_context_equal(const LocaleContext *c, char *l[_VARIABLE_LC_MAX]);

int locale_setup(char ***environment);
