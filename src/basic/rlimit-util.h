/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/resource.h>

#include "macro.h"
#include "missing_resource.h"

const char* rlimit_to_string(int i) _const_;
int rlimit_from_string(const char *s) _pure_;
int rlimit_from_string_harder(const char *s) _pure_;

int setrlimit_closest(int resource, const struct rlimit *rlim);
int setrlimit_closest_all(const struct rlimit * const *rlim, int *which_failed);

int rlimit_parse_one(int resource, const char *val, rlim_t *ret);
int rlimit_parse(int resource, const char *val, struct rlimit *ret);

int rlimit_format(const struct rlimit *rl, char **ret);

int rlimit_copy_all(struct rlimit* target[static _RLIMIT_MAX], struct rlimit* const source[static _RLIMIT_MAX]);
void rlimit_free_all(struct rlimit **rl);

#define RLIMIT_MAKE_CONST(lim) ((struct rlimit) { lim, lim })

int rlimit_nofile_bump(int limit);
int rlimit_nofile_safe(void);

int pid_getrlimit(pid_t pid, int resource, struct rlimit *ret);
