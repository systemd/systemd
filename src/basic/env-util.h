/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include "macro.h"
#include "string.h"

static inline size_t sc_arg_max(void) {
        long l = sysconf(_SC_ARG_MAX);
        assert(l > 0);
        return (size_t) l;
}

bool env_name_is_valid(const char *e);
bool env_value_is_valid(const char *e);
bool env_assignment_is_valid(const char *e);

enum {
        REPLACE_ENV_USE_ENVIRONMENT = 1 << 0,
        REPLACE_ENV_ALLOW_BRACELESS = 1 << 1,
        REPLACE_ENV_ALLOW_EXTENDED  = 1 << 2,
};

char *replace_env_n(const char *format, size_t n, char **env, unsigned flags);
char **replace_env_argv(char **argv, char **env);

static inline char *replace_env(const char *format, char **env, unsigned flags) {
        return replace_env_n(format, strlen(format), env, flags);
}

bool strv_env_is_valid(char **e);
#define strv_env_clean(l) strv_env_clean_with_callback(l, NULL, NULL)
char **strv_env_clean_with_callback(char **l, void (*invalid_callback)(const char *p, void *userdata), void *userdata);

bool strv_env_name_is_valid(char **l);
bool strv_env_name_or_assignment_is_valid(char **l);

char **strv_env_merge(size_t n_lists, ...);
char **strv_env_delete(char **x, size_t n_lists, ...); /* New copy */

char **strv_env_set(char **x, const char *p); /* New copy ... */
char **strv_env_unset(char **l, const char *p); /* In place ... */
char **strv_env_unset_many(char **l, ...) _sentinel_;
int strv_env_replace(char ***l, char *p); /* In place ... */

char *strv_env_get_n(char **l, const char *name, size_t k, unsigned flags) _pure_;
char *strv_env_get(char **x, const char *n) _pure_;

int getenv_bool(const char *p);
int getenv_bool_secure(const char *p);
